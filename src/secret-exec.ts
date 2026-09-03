import { spawn } from "node:child_process";
import type { SecretRegistry } from "./sanitizer.js";
import { sanitizeText } from "./sanitizer.js";

export interface SecretExecOptions {
  command: string;
  cwd: string;
  requestedSecrets: string[];
  availableEnvironment: Readonly<Record<string, string>>;
  registry: SecretRegistry;
  timeoutSeconds: number;
  maxOutputBytes: number;
  signal?: AbortSignal;
}

export interface SecretExecResult {
  text: string;
  details: {
    exitCode: number | null;
    signal: NodeJS.Signals | null;
    timedOut: boolean;
    aborted: boolean;
    truncated: boolean;
    envNames: string[];
  };
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MAX_OUTPUT_LINES = 2000;
const TRUNCATION_NOTICE =
  "[Earlier output truncated; showing the protected tail]";
const ESSENTIAL_ENV_NAMES = new Set([
  "HOME",
  "LANG",
  "LOGNAME",
  "PATH",
  "PWD",
  "SHELL",
  "TERM",
  "TMP",
  "TEMP",
  "TMPDIR",
  "TZ",
  "USER",
  "XDG_CACHE_HOME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
]);

function appendTail(
  current: Buffer,
  chunk: Buffer,
  limit: number,
): { buffer: Buffer; truncated: boolean } {
  const combined = Buffer.concat([current, chunk]);
  if (combined.length <= limit) return { buffer: combined, truncated: false };
  return {
    buffer: combined.subarray(combined.length - limit),
    truncated: true,
  };
}

function buildProcessEnvironment(
  requestedSecrets: string[],
  availableEnvironment: Readonly<Record<string, string>>,
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (
      value !== undefined &&
      (ESSENTIAL_ENV_NAMES.has(name) || name.startsWith("LC_"))
    ) {
      environment[name] = value;
    }
  }
  for (const name of requestedSecrets) {
    const value = availableEnvironment[name];
    if (value !== undefined) environment[name] = value;
  }
  return environment;
}

function truncateProtectedOutput(
  text: string,
  maxBytes: number,
  alreadyTruncated: boolean,
): { text: string; truncated: boolean } {
  const originalLines = text.split("\n");
  const mustTruncate =
    alreadyTruncated ||
    originalLines.length > MAX_OUTPUT_LINES ||
    Buffer.byteLength(text) > maxBytes;
  if (!mustTruncate) return { text, truncated: false };

  const noticeBytes = Buffer.byteLength(`${TRUNCATION_NOTICE}\n`);
  const bodyByteBudget = Math.max(0, maxBytes - noticeBytes);
  let body = originalLines.slice(-(MAX_OUTPUT_LINES - 1)).join("\n");
  if (Buffer.byteLength(body) > bodyByteBudget) {
    const buffer = Buffer.from(body);
    body = buffer.subarray(buffer.length - bodyByteBudget).toString("utf8");
    while (Buffer.byteLength(body) > bodyByteBudget) body = body.slice(1);
  }
  return {
    text: body ? `${TRUNCATION_NOTICE}\n${body}` : TRUNCATION_NOTICE,
    truncated: true,
  };
}

export async function executeWithSecrets(
  options: SecretExecOptions,
): Promise<SecretExecResult> {
  if (options.signal?.aborted)
    throw new Error("Secret command was cancelled before execution.");

  const requestedSecrets = [...new Set(options.requestedSecrets)];
  for (const name of requestedSecrets) {
    if (!ENV_NAME.test(name))
      throw new Error(`Invalid environment variable name: ${name}`);
    const value = options.availableEnvironment[name];
    if (value === undefined)
      throw new Error(`Secret environment variable is not available: ${name}`);
    if (value.length === 0)
      throw new Error(`Secret environment variable is empty: ${name}`);
    if (options.command.includes(value)) {
      throw new Error(
        "Command text contains a plaintext secret; reference its $ENV_NAME instead.",
      );
    }
    // 显式请求即视为秘密，不依赖变量名或 token 格式启发式。
    options.registry.register(value, name, "REQUESTED_SECRET");
  }

  if (
    sanitizeText(options.command, options.registry).text !== options.command
  ) {
    throw new Error(
      "Command text contains a plaintext secret; reference its $ENV_NAME instead.",
    );
  }

  const environment = buildProcessEnvironment(
    requestedSecrets,
    options.availableEnvironment,
  );
  const captureLimit = Math.max(options.maxOutputBytes * 4, 64 * 1024);
  const detached = process.platform !== "win32";

  return new Promise<SecretExecResult>((resolve, reject) => {
    const child = spawn("/bin/sh", ["-c", options.command], {
      cwd: options.cwd,
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
      detached,
    });

    let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
    let truncated = false;
    let timedOut = false;
    let aborted = false;
    let settled = false;
    let forceKill: NodeJS.Timeout | undefined;

    const sendSignal = (signal: NodeJS.Signals): void => {
      try {
        if (detached && child.pid) process.kill(-child.pid, signal);
        else child.kill(signal);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
      }
    };
    const terminate = (): void => {
      sendSignal("SIGTERM");
      if (!forceKill) {
        forceKill = setTimeout(() => sendSignal("SIGKILL"), 1500);
        forceKill.unref();
      }
    };
    const timeout = setTimeout(() => {
      timedOut = true;
      terminate();
    }, options.timeoutSeconds * 1000);
    timeout.unref();

    const abort = (): void => {
      aborted = true;
      terminate();
    };
    options.signal?.addEventListener("abort", abort, { once: true });
    if (options.signal?.aborted) abort();

    child.stdout.on("data", (chunk: Buffer) => {
      const next = appendTail(stdout, chunk, captureLimit);
      stdout = next.buffer;
      truncated ||= next.truncated;
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const next = appendTail(stderr, chunk, captureLimit);
      stderr = next.buffer;
      truncated ||= next.truncated;
    });

    const cleanup = (): void => {
      clearTimeout(timeout);
      if (forceKill) clearTimeout(forceKill);
      options.signal?.removeEventListener("abort", abort);
    };

    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    });

    child.once("close", (exitCode, signal) => {
      if (settled) return;
      settled = true;
      cleanup();

      const sections: string[] = [];
      if (stdout.length > 0) sections.push(stdout.toString("utf8"));
      if (stderr.length > 0)
        sections.push(`[stderr]\n${stderr.toString("utf8")}`);
      const sanitized = sanitizeText(
        sections.join("\n").trimEnd(),
        options.registry,
      );
      const protectedOutput = truncateProtectedOutput(
        sanitized.text,
        options.maxOutputBytes,
        truncated,
      );
      truncated = protectedOutput.truncated;
      let output = protectedOutput.text;
      if (!output) output = "(no output)";

      resolve({
        text: output,
        details: {
          exitCode,
          signal,
          timedOut,
          aborted,
          truncated,
          envNames: requestedSecrets,
        },
      });
    });
  });
}
