import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { describe, it } from "node:test";
import { SecretRegistry } from "../src/sanitizer.js";
import { executeWithSecrets } from "../src/secret-exec.js";

function options(command: string) {
  return {
    command,
    cwd: tmpdir(),
    requestedSecrets: ["OPAQUE_NAME"],
    availableEnvironment: { OPAQUE_NAME: "opaque-selected-value-123456" },
    registry: new SecretRegistry(),
    timeoutSeconds: 5,
    maxOutputBytes: 50 * 1024,
  };
}

describe("secret_exec process isolation", () => {
  it("redacts explicitly selected values even when their names are not heuristic matches", async () => {
    const result = await executeWithSecrets(
      options("printf '%s' \"$OPAQUE_NAME\""),
    );
    assert.equal(result.text, "<secret:OPAQUE_NAME>");
  });

  it("redacts a low-entropy selected secret when it is the complete output", async () => {
    const result = await executeWithSecrets({
      ...options("printf '%s' \"$PASSWORD\""),
      requestedSecrets: ["PASSWORD"],
      availableEnvironment: { PASSWORD: "production" },
    });
    assert.equal(result.text, "<secret:PASSWORD>");
  });

  it("rejects a selected plaintext value embedded in command text", async () => {
    await assert.rejects(
      executeWithSecrets(options("printf 'opaque-selected-value-123456'")),
      /contains a plaintext secret/,
    );
    await assert.rejects(
      executeWithSecrets({
        ...options("printf 'production'"),
        requestedSecrets: ["PASSWORD"],
        availableEnvironment: { PASSWORD: "production" },
      }),
      /contains a plaintext secret/,
    );
  });

  it("enforces the 2000-line output limit", async () => {
    const result = await executeWithSecrets(
      options("i=0; while [ $i -lt 2105 ]; do echo x; i=$((i+1)); done"),
    );
    assert.equal(result.details.truncated, true);
    assert.match(result.text, /^\[Earlier output truncated/);
    assert.ok(result.text.split("\n").length <= 2000);
    assert.ok(Buffer.byteLength(result.text) <= 50 * 1024);
  });

  it("rejects an already-aborted command", async () => {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      executeWithSecrets({ ...options("sleep 10"), signal: controller.signal }),
      /cancelled before execution/,
    );
  });

  it("escalates timeout termination for a shell that ignores SIGTERM", async () => {
    const started = Date.now();
    const result = await executeWithSecrets({
      ...options("trap '' TERM; while :; do sleep 1; done"),
      timeoutSeconds: 1,
    });
    assert.equal(result.details.timedOut, true);
    assert.ok(Date.now() - started < 5000);
  });
});
