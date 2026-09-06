import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

export interface KeyRemoverConfig {
  enabled: boolean;
  capturePastedSecrets: boolean;
  envFiles: string[];
  vaultPath?: string;
  maxOutputBytes: number;
  confirmSecretExec: boolean;
  allowHeadlessSecretExec: boolean;
}

export const DEFAULT_CONFIG: Readonly<KeyRemoverConfig> = {
  enabled: true,
  capturePastedSecrets: true,
  envFiles: [".env", ".env.local"],
  maxOutputBytes: 50 * 1024,
  confirmSecretExec: true,
  allowHeadlessSecretExec: false,
};

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

function expandHome(path: string): string {
  if (path === "~") return homedir();
  if (path.startsWith("~/")) return join(homedir(), path.slice(2));
  return path;
}

export function defaultVaultPath(cwd: string): string {
  const digest = createHash("sha256")
    .update(resolve(cwd))
    .digest("hex")
    .slice(0, 16);
  const project =
    basename(resolve(cwd)).replace(/[^A-Za-z0-9_.-]/g, "_") || "project";
  return join(
    homedir(),
    ".pi",
    "agent",
    "pi-key-remover",
    `${project}-${digest}.env`,
  );
}

export function resolveVaultPath(cwd: string, configuredPath?: string): string {
  if (!configuredPath) return defaultVaultPath(cwd);
  const expanded = expandHome(configuredPath).replaceAll(
    "{projectHash}",
    createHash("sha256").update(resolve(cwd)).digest("hex").slice(0, 16),
  );
  return isAbsolute(expanded) ? expanded : resolve(cwd, expanded);
}

export function parseEnv(content: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(
      line,
    );
    if (!match) continue;
    const name = match[1];
    let value = match[2].trim();
    if (value.startsWith('"') && value.endsWith('"')) {
      try {
        value = JSON.parse(value) as string;
      } catch {
        value = value.slice(1, -1);
      }
    } else if (value.startsWith("'") && value.endsWith("'")) {
      value = value.slice(1, -1);
    } else {
      value = value.replace(/\s+#.*$/, "").trim();
    }
    values[name] = value;
  }
  return values;
}

export function serializeEnv(values: Readonly<Record<string, string>>): string {
  return `${Object.entries(values)
    .filter(([name]) => ENV_NAME.test(name))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, value]) => `${name}=${JSON.stringify(value)}`)
    .join("\n")}\n`;
}

async function readEnvIfPresent(path: string): Promise<Record<string, string>> {
  try {
    return parseEnv(await readFile(path, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return {};
    throw error;
  }
}

export async function loadConfig(
  cwd: string,
  projectTrusted: boolean,
  configDirectoryName = ".pi",
): Promise<KeyRemoverConfig> {
  if (!projectTrusted) return { ...DEFAULT_CONFIG, envFiles: [] };
  const configPath = join(cwd, configDirectoryName, "key-remover.json");
  let userConfig: Partial<KeyRemoverConfig> = {};
  try {
    userConfig = JSON.parse(
      await readFile(configPath, "utf8"),
    ) as Partial<KeyRemoverConfig>;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  return {
    enabled:
      typeof userConfig.enabled === "boolean"
        ? userConfig.enabled
        : DEFAULT_CONFIG.enabled,
    capturePastedSecrets:
      typeof userConfig.capturePastedSecrets === "boolean"
        ? userConfig.capturePastedSecrets
        : DEFAULT_CONFIG.capturePastedSecrets,
    envFiles: Array.isArray(userConfig.envFiles)
      ? userConfig.envFiles.filter(
          (entry): entry is string => typeof entry === "string",
        )
      : [...DEFAULT_CONFIG.envFiles],
    vaultPath:
      typeof userConfig.vaultPath === "string"
        ? userConfig.vaultPath
        : undefined,
    maxOutputBytes:
      typeof userConfig.maxOutputBytes === "number" &&
      Number.isInteger(userConfig.maxOutputBytes)
        ? Math.max(1024, Math.min(userConfig.maxOutputBytes, 50 * 1024))
        : DEFAULT_CONFIG.maxOutputBytes,
    confirmSecretExec:
      typeof userConfig.confirmSecretExec === "boolean"
        ? userConfig.confirmSecretExec
        : DEFAULT_CONFIG.confirmSecretExec,
    allowHeadlessSecretExec:
      typeof userConfig.allowHeadlessSecretExec === "boolean"
        ? userConfig.allowHeadlessSecretExec
        : DEFAULT_CONFIG.allowHeadlessSecretExec,
  };
}

export async function loadSecretEnvironment(
  cwd: string,
  config: KeyRemoverConfig,
  projectTrusted: boolean,
): Promise<Record<string, string>> {
  const values: Record<string, string> = {};
  if (projectTrusted) {
    for (const configuredPath of config.envFiles) {
      const expanded = expandHome(configuredPath);
      const path = isAbsolute(expanded) ? expanded : resolve(cwd, expanded);
      Object.assign(values, await readEnvIfPresent(path));
    }
  }

  // 项目 vault 仅在项目受信任时恢复，避免全局安装的扩展向未受信目录暴露旧密钥。
  // 优先级为 process.env > vault > 后加载的 envFiles > 先加载的 envFiles。
  if (projectTrusted) {
    Object.assign(
      values,
      await readEnvIfPresent(resolveVaultPath(cwd, config.vaultPath)),
    );
  }

  for (const [name, value] of Object.entries(process.env)) {
    if (value !== undefined) values[name] = value;
  }
  return values;
}

async function replaceVaultContents(
  vaultPath: string,
  config: KeyRemoverConfig,
  values: Readonly<Record<string, string>>,
): Promise<void> {
  const directory = dirname(vaultPath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  // 仅收紧扩展自有默认目录；自定义路径的父目录可能是项目根目录或共享系统目录。
  if (!config.vaultPath) await chmod(directory, 0o700);

  const temporaryPath = `${vaultPath}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(temporaryPath, serializeEnv(values), {
    encoding: "utf8",
    mode: 0o600,
  });
  await chmod(temporaryPath, 0o600);
  await rename(temporaryPath, vaultPath);
  await chmod(vaultPath, 0o600);
}

export async function listPersistedSecretNames(
  cwd: string,
  config: KeyRemoverConfig,
): Promise<string[]> {
  const vault = await readEnvIfPresent(resolveVaultPath(cwd, config.vaultPath));
  return Object.keys(vault).sort((left, right) => left.localeCompare(right));
}

export async function deletePersistedSecret(
  cwd: string,
  config: KeyRemoverConfig,
  envName: string,
): Promise<boolean> {
  const vaultPath = resolveVaultPath(cwd, config.vaultPath);
  const current = await readEnvIfPresent(vaultPath);
  if (!Object.hasOwn(current, envName)) return false;

  const next = { ...current };
  delete next[envName];
  await replaceVaultContents(vaultPath, config, next);
  return true;
}

export async function persistSecrets(
  cwd: string,
  config: KeyRemoverConfig,
  secrets: Readonly<Record<string, string>>,
): Promise<string> {
  const vaultPath = resolveVaultPath(cwd, config.vaultPath);
  const current = await readEnvIfPresent(vaultPath);
  const next = { ...current, ...secrets };
  await replaceVaultContents(vaultPath, config, next);
  return vaultPath;
}
