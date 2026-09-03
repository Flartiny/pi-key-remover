export interface DetectedSecret {
  envName: string;
  placeholder: string;
  type: string;
  value: string;
}

export interface SanitizeResult {
  text: string;
  replacements: number;
  secrets: DetectedSecret[];
}

type SecretMatchMode = "global" | "contextual";

interface Candidate {
  start: number;
  end: number;
  value: string;
  type: string;
  preferredEnvName: string;
  priority: number;
  matchMode: SecretMatchMode;
}

interface RegisteredSecret {
  envName: string;
  placeholder: string;
  type: string;
  value: string;
  matchMode: SecretMatchMode;
}

interface ProtectedRange {
  start: number;
  end: number;
}

const MIN_SECRET_LENGTH = 8;
const GLOBAL_SECRET_MIN_LENGTH = 12;
const GLOBAL_SECRET_MIN_UNIQUE_CHARACTERS = 8;
const GLOBAL_SECRET_MIN_ENTROPY = 3;
const SECRET_REFERENCE =
  /^(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}|<secret:[^>]+>|\[REDACTED(?::[^\]]+)?\])$/i;
const GENERATED_PLACEHOLDER = new RegExp(
  "<" + "secret:[A-Za-z_][A-Za-z0-9_]*>",
  "g",
);

const KNOWN_PATTERNS: ReadonlyArray<{
  type: string;
  envName: string;
  regex: RegExp;
}> = [
  {
    type: "ANTHROPIC_API_KEY",
    envName: "ANTHROPIC_API_KEY",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: "OPENAI_API_KEY",
    envName: "OPENAI_API_KEY",
    regex: /\bsk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: "GITHUB_TOKEN",
    envName: "GITHUB_TOKEN",
    regex: /\b(?:github_pat_[A-Za-z0-9_]{30,}|gh[pousr]_[A-Za-z0-9]{30,})\b/g,
  },
  {
    type: "GITLAB_TOKEN",
    envName: "GITLAB_TOKEN",
    regex: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: "GOOGLE_API_KEY",
    envName: "GOOGLE_API_KEY",
    regex: /\bAIza[A-Za-z0-9_-]{30,}\b/g,
  },
  {
    type: "AWS_ACCESS_KEY_ID",
    envName: "AWS_ACCESS_KEY_ID",
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  },
  {
    type: "SLACK_TOKEN",
    envName: "SLACK_TOKEN",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
  },
  {
    type: "STRIPE_SECRET_KEY",
    envName: "STRIPE_SECRET_KEY",
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  },
  {
    type: "NPM_TOKEN",
    envName: "NPM_TOKEN",
    regex: /\bnpm_[A-Za-z0-9]{30,}\b/g,
  },
  {
    type: "PYPI_TOKEN",
    envName: "PYPI_API_TOKEN",
    regex: /\bpypi-[A-Za-z0-9_-]{30,}\b/g,
  },
  {
    type: "HUGGINGFACE_TOKEN",
    envName: "HF_TOKEN",
    regex: /\bhf_[A-Za-z0-9]{20,}\b/g,
  },
  {
    type: "JWT",
    envName: "AUTH_TOKEN",
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  {
    type: "SLACK_WEBHOOK_URL",
    envName: "SLACK_WEBHOOK_URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,}/g,
  },
  {
    type: "DISCORD_WEBHOOK_URL",
    envName: "DISCORD_WEBHOOK_URL",
    regex:
      /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]{20,}/g,
  },
];

const SENSITIVE_ENV_NAME_PART =
  "(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|WEBHOOK|DATABASE_URL|DSN|CONNECTION_STRING|COOKIE)";
const SENSITIVE_ENV_NAME = new RegExp(SENSITIVE_ENV_NAME_PART, "i");
const GENERIC_ASSIGNMENT =
  /(?:["']?)([A-Za-z_][A-Za-z0-9_]*)(?:["']?)\s*(?:=|:)\s*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})'|([A-Za-z0-9._~+/@%:=?$&*-]{8,}))/gi;
const BEARER_TOKEN = /\bBearer\s+([A-Za-z0-9._~+/-]{16,}=*)/gi;
const BASIC_URL_CREDENTIAL =
  /\b[a-z][a-z0-9+.-]*:\/\/[^\s/@:]+:([^\s/@]{8,})@/gi;
const PRIVATE_KEY_BLOCK =
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g;

function normalizeEnvName(name: string): string {
  const normalized = name
    .toUpperCase()
    .replace(/[^A-Z0-9_]/g, "_")
    .replace(/_+/g, "_");
  if (/^[A-Z_]/.test(normalized)) return normalized;
  return `PI_${normalized}`;
}

function isPlausibleSecret(value: string): boolean {
  return value.length >= MIN_SECRET_LENGTH && !SECRET_REFERENCE.test(value);
}

function characterClassCount(value: string): number {
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((pattern) =>
    pattern.test(value),
  ).length;
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function defaultSecretMatchMode(value: string): SecretMatchMode {
  const uniqueCharacters = new Set(value).size;
  if (uniqueCharacters < GLOBAL_SECRET_MIN_UNIQUE_CHARACTERS)
    return "contextual";

  const entropy = shannonEntropy(value);
  const looksLikeShortNaturalLanguageWord =
    /^[A-Za-z]+$/.test(value) && value.length < 20;
  if (looksLikeShortNaturalLanguageWord) return "contextual";

  if (value.length >= 20 && entropy >= GLOBAL_SECRET_MIN_ENTROPY)
    return "global";
  if (
    value.length >= GLOBAL_SECRET_MIN_LENGTH &&
    characterClassCount(value) >= 3 &&
    entropy >= GLOBAL_SECRET_MIN_ENTROPY
  )
    return "global";
  return "contextual";
}

export function isSensitiveEnvName(name: string): boolean {
  return SENSITIVE_ENV_NAME.test(name);
}

export class SecretRegistry {
  private readonly byValue = new Map<string, RegisteredSecret>();
  private readonly valueByEnvName = new Map<string, string>();

  register(
    value: string,
    preferredEnvName: string,
    type = "SECRET",
    matchMode = defaultSecretMatchMode(value),
  ): RegisteredSecret {
    const existing = this.byValue.get(value);
    if (existing) {
      if (matchMode === "global") existing.matchMode = "global";
      return existing;
    }

    const baseName = normalizeEnvName(preferredEnvName || "PI_SECRET");
    let envName = baseName;
    let suffix = 2;
    while (
      this.valueByEnvName.has(envName) &&
      this.valueByEnvName.get(envName) !== value
    ) {
      envName = `${baseName}_${suffix}`;
      suffix += 1;
    }

    const registered: RegisteredSecret = {
      envName,
      placeholder: `<secret:${envName}>`,
      type,
      value,
      matchMode,
    };
    this.byValue.set(value, registered);
    this.valueByEnvName.set(envName, value);
    return registered;
  }

  preload(env: Readonly<Record<string, string>>): void {
    for (const [name, value] of Object.entries(env)) {
      if (isSensitiveEnvName(name) && isPlausibleSecret(value)) {
        this.register(value, name, "ENV_SECRET");
      }
    }
  }

  getRegisteredSecrets(): ReadonlyArray<RegisteredSecret> {
    return [...this.byValue.values()];
  }
}

function addRegexCandidates(
  text: string,
  regex: RegExp,
  makeCandidate: (
    match: RegExpExecArray,
    value: string,
    start: number,
  ) => Omit<Candidate, "start" | "end" | "value">,
  candidates: Candidate[],
  captureGroup = 0,
): void {
  for (const match of text.matchAll(regex)) {
    const value = match[captureGroup];
    if (!value || match.index === undefined || !isPlausibleSecret(value))
      continue;
    const relativeStart = captureGroup === 0 ? 0 : match[0].lastIndexOf(value);
    const start = match.index + relativeStart;
    const metadata = makeCandidate(match, value, start);
    candidates.push({ start, end: start + value.length, value, ...metadata });
  }
}

function addContextualLineCandidates(
  text: string,
  secret: RegisteredSecret,
  candidates: Candidate[],
): void {
  let lineStart = 0;
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === secret.value) {
      const leadingWhitespace = line.length - line.trimStart().length;
      const start = lineStart + leadingWhitespace;
      candidates.push({
        start,
        end: start + secret.value.length,
        value: secret.value,
        type: secret.type,
        preferredEnvName: secret.envName,
        priority: 1000,
        matchMode: "contextual",
      });
    }
    lineStart += line.length + 1;
  }
}

function collectProtectedRanges(text: string): ProtectedRange[] {
  const ranges: ProtectedRange[] = [];
  for (const match of text.matchAll(GENERATED_PLACEHOLDER)) {
    if (match.index === undefined) continue;
    ranges.push({ start: match.index, end: match.index + match[0].length });
  }
  return ranges;
}

function overlapsProtectedRange(
  candidate: Candidate,
  ranges: ReadonlyArray<ProtectedRange>,
): boolean {
  return ranges.some(
    (range) => candidate.start < range.end && candidate.end > range.start,
  );
}

function collectCandidates(
  text: string,
  registry: SecretRegistry,
): Candidate[] {
  const candidates: Candidate[] = [];

  for (const secret of registry.getRegisteredSecrets()) {
    if (secret.matchMode === "contextual") {
      addContextualLineCandidates(text, secret, candidates);
      continue;
    }

    let start = text.indexOf(secret.value);
    while (start >= 0) {
      candidates.push({
        start,
        end: start + secret.value.length,
        value: secret.value,
        type: secret.type,
        preferredEnvName: secret.envName,
        priority: 1000,
        matchMode: "global",
      });
      start = text.indexOf(secret.value, start + secret.value.length);
    }
  }

  addRegexCandidates(
    text,
    PRIVATE_KEY_BLOCK,
    () => ({
      type: "PRIVATE_KEY",
      preferredEnvName: "PRIVATE_KEY",
      priority: 200,
      matchMode: "global",
    }),
    candidates,
  );

  for (const pattern of KNOWN_PATTERNS) {
    addRegexCandidates(
      text,
      pattern.regex,
      () => ({
        type: pattern.type,
        preferredEnvName: pattern.envName,
        priority: 100,
        matchMode: "global",
      }),
      candidates,
    );
  }

  for (const match of text.matchAll(GENERIC_ASSIGNMENT)) {
    if (match.index === undefined) continue;
    const rawValue = match[2] ?? match[3] ?? match[4];
    const value = match[4] ? rawValue?.replace(/[.!?]+$/, "") : rawValue;
    const envName = match[1];
    if (
      !value ||
      !envName ||
      !isSensitiveEnvName(envName) ||
      !isPlausibleSecret(value)
    )
      continue;
    const start = match.index + match[0].lastIndexOf(rawValue ?? value);
    candidates.push({
      start,
      end: start + value.length,
      value,
      type: "ASSIGNED_SECRET",
      preferredEnvName: envName,
      priority: 300,
      matchMode: defaultSecretMatchMode(value),
    });
  }

  addRegexCandidates(
    text,
    BEARER_TOKEN,
    (_match, value) => ({
      type: "BEARER_TOKEN",
      preferredEnvName: "AUTH_TOKEN",
      priority: 50,
      matchMode: defaultSecretMatchMode(value),
    }),
    candidates,
    1,
  );

  addRegexCandidates(
    text,
    BASIC_URL_CREDENTIAL,
    (_match, value) => ({
      type: "URL_PASSWORD",
      preferredEnvName: "URL_PASSWORD",
      priority: 50,
      matchMode: defaultSecretMatchMode(value),
    }),
    candidates,
    1,
  );

  const protectedRanges = collectProtectedRanges(text);
  return candidates.filter(
    (candidate) => !overlapsProtectedRange(candidate, protectedRanges),
  );
}

function selectNonOverlapping(candidates: Candidate[]): Candidate[] {
  const sorted = [...candidates].sort(
    (left, right) =>
      left.start - right.start ||
      right.priority - left.priority ||
      right.end - right.start - (left.end - left.start),
  );
  const selected: Candidate[] = [];
  let occupiedUntil = -1;
  for (const candidate of sorted) {
    if (candidate.start < occupiedUntil) continue;
    selected.push(candidate);
    occupiedUntil = candidate.end;
  }
  return selected;
}

export function sanitizeText(
  text: string,
  registry: SecretRegistry,
): SanitizeResult {
  const candidates = selectNonOverlapping(collectCandidates(text, registry));
  if (candidates.length === 0) return { text, replacements: 0, secrets: [] };

  const secrets = new Map<string, DetectedSecret>();
  let cursor = 0;
  let sanitized = "";
  for (const candidate of candidates) {
    const registered = registry.register(
      candidate.value,
      candidate.preferredEnvName,
      candidate.type,
      candidate.matchMode,
    );
    sanitized += text.slice(cursor, candidate.start) + registered.placeholder;
    cursor = candidate.end;
    secrets.set(registered.envName, registered);
  }
  sanitized += text.slice(cursor);

  return {
    text: sanitized,
    replacements: candidates.length,
    secrets: [...secrets.values()],
  };
}
