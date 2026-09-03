import {
  CONFIG_DIR_NAME,
  type ExtensionAPI,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
  type KeyRemoverConfig,
  loadConfig,
  loadSecretEnvironment,
  persistSecrets,
  resolveVaultPath,
} from "./env-store.js";
import {
  type DetectedSecret,
  sanitizeText,
  SecretRegistry,
} from "./sanitizer.js";
import { executeWithSecrets } from "./secret-exec.js";

const STATE_ENTRY_TYPE = "pi-key-remover-state";
const STATUS_ID = "pi-key-remover";

interface RuntimeState {
  cwd: string;
  trusted: boolean;
  config: KeyRemoverConfig;
  enabled: boolean;
  capturePastedSecrets: boolean;
  environment: Record<string, string>;
  registry: SecretRegistry;
}

interface PersistedState {
  enabled?: boolean;
  capturePastedSecrets?: boolean;
}

const OPAQUE_CONTENT_TYPES = new Set([
  "image",
  "image_url",
  "input_image",
  "thinking",
  "reasoning",
  "redacted_thinking",
]);
const OPAQUE_PROTOCOL_FIELDS = new Set([
  "signature",
  "encrypted_content",
  "encryptedContent",
  "thinkingSignature",
  "thoughtSignature",
]);

function sanitizeValue<T>(
  value: T,
  registry: SecretRegistry,
  seen = new WeakMap<object, unknown>(),
): T {
  if (typeof value === "string") return sanitizeText(value, registry).text as T;
  if (value === null || typeof value !== "object") return value;
  if (seen.has(value)) return seen.get(value) as T;
  if (Array.isArray(value)) {
    const copy: unknown[] = [];
    seen.set(value, copy);
    for (const entry of value) copy.push(sanitizeValue(entry, registry, seen));
    return copy as T;
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) return value;
  const record = value as Record<string, unknown>;
  const contentType = typeof record.type === "string" ? record.type : undefined;
  if (contentType && OPAQUE_CONTENT_TYPES.has(contentType)) return value;

  const copy: Record<string, unknown> = {};
  seen.set(value, copy);
  for (const [key, entry] of Object.entries(record)) {
    copy[key] = OPAQUE_PROTOCOL_FIELDS.has(key)
      ? entry
      : sanitizeValue(entry, registry, seen);
  }
  return copy as T;
}

function sanitizeMessage<T>(
  message: T,
  registry: SecretRegistry,
): { message: T; replacements: number; secrets: DetectedSecret[] } {
  if (message === null || typeof message !== "object") {
    return { message, replacements: 0, secrets: [] };
  }

  const original = message as Record<string, unknown>;
  const copy: Record<string, unknown> = { ...original };
  const discovered = new Map<string, DetectedSecret>();
  let replacements = 0;
  const scanText = (text: string): string => {
    const result = sanitizeText(text, registry);
    replacements += result.replacements;
    for (const secret of result.secrets) discovered.set(secret.envName, secret);
    return result.text;
  };

  if (typeof original.content === "string") {
    copy.content = scanText(original.content);
  } else if (Array.isArray(original.content)) {
    copy.content = original.content.map((part) => {
      if (part === null || typeof part !== "object") return part;
      const originalPart = part as Record<string, unknown>;
      const contentType =
        typeof originalPart.type === "string" ? originalPart.type : undefined;
      if (contentType && OPAQUE_CONTENT_TYPES.has(contentType)) return part;
      const nextPart: Record<string, unknown> = { ...originalPart };
      if (typeof originalPart.text === "string")
        nextPart.text = scanText(originalPart.text);
      if (originalPart.type === "toolCall" && "arguments" in originalPart) {
        nextPart.arguments = sanitizeValue(originalPart.arguments, registry);
      }
      return nextPart;
    });
  }
  if ("details" in original)
    copy.details = sanitizeValue(original.details, registry);

  return {
    message: copy as T,
    replacements,
    secrets: [...discovered.values()],
  };
}

function updateStatus(ctx: ExtensionContext, state: RuntimeState): void {
  if (!ctx.hasUI) return;
  ctx.ui.setStatus(STATUS_ID, state.enabled ? "keys: protected" : "keys: OFF");
}

function restorePersistedState(
  ctx: ExtensionContext,
  state: RuntimeState,
): void {
  for (const entry of ctx.sessionManager.getBranch()) {
    if (entry.type !== "custom" || entry.customType !== STATE_ENTRY_TYPE)
      continue;
    const saved = entry.data as PersistedState | undefined;
    if (typeof saved?.enabled === "boolean") state.enabled = saved.enabled;
    if (typeof saved?.capturePastedSecrets === "boolean") {
      state.capturePastedSecrets = saved.capturePastedSecrets;
    }
  }
}

function appendState(pi: ExtensionAPI, state: RuntimeState): void {
  pi.appendEntry(STATE_ENTRY_TYPE, {
    enabled: state.enabled,
    capturePastedSecrets: state.capturePastedSecrets,
  } satisfies PersistedState);
}

async function reloadEnvironment(state: RuntimeState): Promise<void> {
  state.environment = await loadSecretEnvironment(
    state.cwd,
    state.config,
    state.trusted,
  );
  state.registry = new SecretRegistry();
  state.registry.preload(state.environment);
}

async function retainDetectedSecrets(
  state: RuntimeState,
  secrets: ReadonlyArray<{ envName: string; value: string }>,
): Promise<void> {
  if (secrets.length === 0) return;
  const values: Record<string, string> = {};
  for (const secret of secrets) {
    state.environment[secret.envName] = secret.value;
    values[secret.envName] = secret.value;
  }
  if (state.capturePastedSecrets)
    await persistSecrets(state.cwd, state.config, values);
}

function commandHelp(): string {
  return "Usage: /key-remover [on|off|toggle|status|capture on|capture off|reload]";
}

export default function keyRemoverExtension(pi: ExtensionAPI): void {
  let state: RuntimeState = {
    cwd: process.cwd(),
    trusted: false,
    config: {
      enabled: true,
      capturePastedSecrets: true,
      envFiles: [],
      maxOutputBytes: 50 * 1024,
      confirmSecretExec: true,
      allowHeadlessSecretExec: false,
    },
    enabled: true,
    capturePastedSecrets: true,
    environment: {},
    registry: new SecretRegistry(),
  };

  pi.on("session_start", async (_event, ctx) => {
    const trusted = ctx.isProjectTrusted();
    const config = await loadConfig(ctx.cwd, trusted, CONFIG_DIR_NAME);
    state = {
      cwd: ctx.cwd,
      trusted,
      config,
      enabled: config.enabled,
      capturePastedSecrets: config.capturePastedSecrets,
      environment: {},
      registry: new SecretRegistry(),
    };
    restorePersistedState(ctx, state);
    await reloadEnvironment(state);
    updateStatus(ctx, state);
  });

  pi.on("session_shutdown", async (_event, ctx) => {
    if (ctx.hasUI) ctx.ui.setStatus(STATUS_ID, undefined);
  });

  pi.on("input", async (event, ctx) => {
    if (!state.enabled) return { action: "continue" };
    const result = sanitizeText(event.text, state.registry);
    if (result.replacements === 0) return { action: "continue" };

    try {
      await retainDetectedSecrets(state, result.secrets);
    } catch (error) {
      ctx.ui.notify(
        `Secret was redacted but could not be saved: ${(error as Error).message}`,
        "warning",
      );
    }

    const names = result.secrets
      .map((secret) => `$${secret.envName}`)
      .join(", ");
    ctx.ui.notify(
      `Protected ${result.replacements} secret occurrence(s)${names ? `; available as ${names}` : ""}.`,
      "info",
    );
    return { action: "transform", text: result.text, images: event.images };
  });

  // input 之后 template/skill 才会展开；message_end 是写入 session 前的最后一道持久化保护。
  pi.on("message_end", async (event, ctx) => {
    if (!state.enabled) return;
    const result = sanitizeMessage(event.message, state.registry);
    if (event.message.role === "user" && result.secrets.length > 0) {
      try {
        await retainDetectedSecrets(state, result.secrets);
      } catch (error) {
        ctx.ui.notify(
          `Secret was redacted but could not be saved: ${(error as Error).message}`,
          "warning",
        );
      }
    }
    return { message: result.message };
  });

  pi.on("before_agent_start", async (event) => {
    if (!state.enabled) return;
    const systemPrompt = sanitizeText(event.systemPrompt, state.registry).text;
    if (systemPrompt !== event.systemPrompt) return { systemPrompt };
  });

  pi.on("context", async (event) => {
    if (!state.enabled) return;
    return {
      messages: event.messages.map(
        (message) => sanitizeMessage(message, state.registry).message,
      ),
    };
  });

  pi.on("before_provider_request", async (event) => {
    if (!state.enabled) return;
    return sanitizeValue(event.payload, state.registry);
  });

  pi.on("tool_result", async (event) => {
    if (!state.enabled) return;
    return {
      content: sanitizeValue(event.content, state.registry),
      details: sanitizeValue(event.details, state.registry),
    };
  });

  const handleCommand = async (
    rawArgs: string,
    ctx: ExtensionContext,
  ): Promise<void> => {
    const args = rawArgs.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const action = args[0] ?? "status";

    if (action === "on") state.enabled = true;
    else if (action === "off") state.enabled = false;
    else if (action === "toggle") state.enabled = !state.enabled;
    else if (action === "capture" && args[1] === "on")
      state.capturePastedSecrets = true;
    else if (action === "capture" && args[1] === "off")
      state.capturePastedSecrets = false;
    else if (action === "reload") {
      await reloadEnvironment(state);
      ctx.ui.notify("Key remover environment reloaded.", "info");
    } else if (action !== "status") {
      ctx.ui.notify(commandHelp(), "warning");
      return;
    }

    if (action !== "status" && action !== "reload") appendState(pi, state);
    updateStatus(ctx, state);
    ctx.ui.notify(
      `Key remover: ${state.enabled ? "ON" : "OFF"}; capture: ${state.capturePastedSecrets ? "ON" : "OFF"}; secrets available: ${Object.keys(state.environment).filter((name) => state.registry.getRegisteredSecrets().some((secret) => secret.envName === name)).length}.`,
      state.enabled ? "info" : "warning",
    );
  };

  pi.registerCommand("key-remover", {
    description: "Toggle API key/token protection or show its status",
    handler: handleCommand,
  });
  pi.registerCommand("kr", {
    description: "Short alias for /key-remover",
    handler: handleCommand,
  });

  pi.registerTool({
    name: "secret_exec",
    label: "Secret Exec",
    description:
      "Run a user-approved shell command with explicitly selected secrets injected as environment variables. Use $ENV_NAME in the command; never place a secret value in command text. Output is redacted before entering context.",
    promptSnippet:
      "Run commands with protected environment secrets without exposing their values",
    promptGuidelines: [
      "Use secret_exec when an operation needs a key represented by a <secret:ENV_NAME> placeholder; reference it as $ENV_NAME and never print, encode, or otherwise expose the value.",
      "Never use bash to source or print secret files when secret_exec can inject only the required variables.",
    ],
    parameters: Type.Object({
      command: Type.String({
        description:
          "Shell command. Reference secrets as $ENV_NAME, never as plaintext.",
      }),
      secrets: Type.Array(
        Type.String({ pattern: "^[A-Za-z_][A-Za-z0-9_]*$" }),
        {
          description: "Environment variable names to inject",
          minItems: 1,
          uniqueItems: true,
        },
      ),
      timeoutSeconds: Type.Optional(Type.Integer({ minimum: 1, maximum: 600 })),
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      if (
        sanitizeText(params.command, state.registry).text !== params.command
      ) {
        throw new Error(
          "Command text contains a plaintext secret; reference its $ENV_NAME instead.",
        );
      }
      if (state.config.confirmSecretExec) {
        if (!ctx.hasUI && !state.config.allowHeadlessSecretExec) {
          throw new Error(
            "secret_exec requires interactive approval in this mode. Set allowHeadlessSecretExec only in a trusted configuration.",
          );
        }
        if (ctx.hasUI) {
          const approved = await ctx.ui.confirm(
            "Allow secret command?",
            `Inject: ${params.secrets.join(", ")}\n\n${params.command}`,
          );
          if (!approved)
            throw new Error("Secret command was declined by the user.");
        }
      }

      const result = await executeWithSecrets({
        command: params.command,
        cwd: ctx.cwd,
        requestedSecrets: params.secrets,
        availableEnvironment: state.environment,
        registry: state.registry,
        timeoutSeconds: params.timeoutSeconds ?? 120,
        maxOutputBytes: state.config.maxOutputBytes,
        signal,
      });
      return {
        content: [{ type: "text", text: result.text }],
        details: result.details,
      };
    },
  });
}

export { resolveVaultPath };
