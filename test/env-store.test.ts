import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  loadSecretEnvironment,
  parseEnv,
  persistSecrets,
  serializeEnv,
  type KeyRemoverConfig,
} from "../src/env-store.js";

const TEST_CONFIG: KeyRemoverConfig = {
  enabled: true,
  capturePastedSecrets: true,
  envFiles: [],
  vaultPath: "vault.env",
  maxOutputBytes: 50 * 1024,
  confirmSecretExec: true,
  allowHeadlessSecretExec: false,
};

describe("environment storage", () => {
  it("parses dotenv values without executing shell syntax", () => {
    const parsed = parseEnv(
      [
        "PLAIN_TOKEN=abc123456",
        'QUOTED_API_KEY="a value with spaces"',
        "export SINGLE_SECRET='literal $HOME'",
        "NOT_SHELL=$(touch /tmp/should-not-run)",
        "# ignored",
      ].join("\n"),
    );

    assert.deepEqual(parsed, {
      PLAIN_TOKEN: "abc123456",
      QUOTED_API_KEY: "a value with spaces",
      SINGLE_SECRET: "literal $HOME",
      NOT_SHELL: "$(touch /tmp/should-not-run)",
    });
  });

  it("serializes values in a dotenv-safe quoted form", () => {
    const serialized = serializeEnv({
      TOKEN: "line1\nline2",
      API_KEY: "a b",
      "bad-name": "ignored",
    });
    assert.equal(serialized, 'API_KEY="a b"\nTOKEN="line1\\nline2"\n');
    assert.deepEqual(parseEnv(serialized), {
      API_KEY: "a b",
      TOKEN: "line1\nline2",
    });
  });

  it("uses process.env ahead of vault and env files", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "pi-key-remover-precedence-"));
    const config = { ...TEST_CONFIG, envFiles: [".env"] };
    await writeFile(join(cwd, ".env"), "PRECEDENCE_API_KEY=from-env-file\n");
    await persistSecrets(cwd, config, { PRECEDENCE_API_KEY: "from-vault" });
    const original = process.env.PRECEDENCE_API_KEY;
    process.env.PRECEDENCE_API_KEY = "from-process";
    try {
      const environment = await loadSecretEnvironment(cwd, config, true);
      assert.equal(environment.PRECEDENCE_API_KEY, "from-process");
    } finally {
      if (original === undefined) delete process.env.PRECEDENCE_API_KEY;
      else process.env.PRECEDENCE_API_KEY = original;
    }
  });

  it("persists a merged vault with owner-only permissions without changing a custom parent", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "pi-key-remover-"));
    await chmod(cwd, 0o755);
    const path = await persistSecrets(cwd, TEST_CONFIG, {
      FIRST_TOKEN: "first-value",
    });
    await persistSecrets(cwd, TEST_CONFIG, { SECOND_API_KEY: "second-value" });

    assert.deepEqual(parseEnv(await readFile(path, "utf8")), {
      FIRST_TOKEN: "first-value",
      SECOND_API_KEY: "second-value",
    });
    assert.equal((await stat(path)).mode & 0o777, 0o600);
    assert.equal((await stat(cwd)).mode & 0o777, 0o755);
  });
});
