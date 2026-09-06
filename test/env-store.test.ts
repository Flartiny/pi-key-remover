import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  deletePersistedSecret,
  listPersistedSecretNames,
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

  it("lists and atomically deletes one captured vault entry", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "pi-key-remover-delete-"));
    const firstName = ["FIRST", "TOKEN"].join("_");
    const secondName = ["SECOND", "API", "KEY"].join("_");
    await persistSecrets(cwd, TEST_CONFIG, {
      [firstName]: `first-${"A1b2C3d4".repeat(3)}`,
      [secondName]: `second-${"Q7w8E9r0".repeat(3)}`,
    });

    assert.deepEqual(await listPersistedSecretNames(cwd, TEST_CONFIG), [
      firstName,
      secondName,
    ]);
    assert.equal(
      await deletePersistedSecret(cwd, TEST_CONFIG, secondName),
      true,
    );
    assert.equal(
      await deletePersistedSecret(cwd, TEST_CONFIG, secondName),
      false,
    );
    assert.deepEqual(parseEnv(await readFile(join(cwd, "vault.env"), "utf8")), {
      [firstName]: `first-${"A1b2C3d4".repeat(3)}`,
    });
    assert.equal((await stat(join(cwd, "vault.env"))).mode & 0o777, 0o600);
  });

  it("returns an empty captured-key list when the vault does not exist", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "pi-key-remover-empty-vault-"));
    assert.deepEqual(await listPersistedSecretNames(cwd, TEST_CONFIG), []);
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
