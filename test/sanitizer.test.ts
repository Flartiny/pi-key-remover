import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { sanitizeText, SecretRegistry } from "../src/sanitizer.js";

const OPENAI_KEY = `sk-proj-${"A1b2C3d4".repeat(5)}`;
const GITHUB_TOKEN = `ghp_${"aB3".repeat(14)}`;

function placeholder(envName: string): string {
  return "<" + `secret:${envName}` + ">";
}

describe("sanitizeText", () => {
  it("redacts known platform keys while preserving readable context", () => {
    const registry = new SecretRegistry();
    const result = sanitizeText(
      `Use ${OPENAI_KEY} to list the models.`,
      registry,
    );

    assert.equal(
      result.text,
      "Use <secret:OPENAI_API_KEY> to list the models.",
    );
    assert.equal(result.replacements, 1);
    assert.equal(result.secrets[0]?.envName, "OPENAI_API_KEY");
    assert.ok(!result.text.includes(OPENAI_KEY));
  });

  it("keeps generated placeholders stable across repeated sanitization", () => {
    const registry = new SecretRegistry();
    registry.preload({
      SECRET: `ambient-${"A1b2C3d4".repeat(3)}`,
    });

    const first = sanitizeText(`Use ${OPENAI_KEY}`, registry);
    const expected = `Use ${placeholder("OPENAI_API_KEY")}`;
    assert.equal(first.text, expected);

    for (let pass = 0; pass < 4; pass += 1) {
      assert.deepEqual(sanitizeText(first.text, registry), {
        text: expected,
        replacements: 0,
        secrets: [],
      });
    }
    const legacyNestedPlaceholder = placeholder(placeholder("SECRET_2"));
    assert.deepEqual(sanitizeText(legacyNestedPlaceholder, registry), {
      text: legacyNestedPlaceholder,
      replacements: 0,
      secrets: [],
    });

    assert.deepEqual(
      registry
        .getRegisteredSecrets()
        .map((secret) => secret.envName)
        .sort(),
      ["OPENAI_API_KEY", "SECRET"],
    );
  });

  it("uses assignment names and stable placeholders for repeated values", () => {
    const registry = new SecretRegistry();
    const text = `DEPLOY_API_TOKEN=${GITHUB_TOKEN}，请查询仓库。\nReuse ${GITHUB_TOKEN}.`;
    const result = sanitizeText(text, registry);

    assert.equal(
      result.text,
      "DEPLOY_API_TOKEN=<secret:DEPLOY_API_TOKEN>，请查询仓库。\nReuse <secret:DEPLOY_API_TOKEN>.",
    );
    assert.equal(result.replacements, 2);
    assert.deepEqual(
      result.secrets.map((secret) => secret.envName),
      ["DEPLOY_API_TOKEN"],
    );
  });

  it("keeps generic sensitive names aligned and detects Stripe test keys", () => {
    const registry = new SecretRegistry();
    const stripe = `sk_test_${"Ab9".repeat(8)}`;
    const result = sanitizeText(
      `COOKIE=opaque-session-value-123456 CREDENTIAL=opaque-credential-123456 DATABASE_URL=postgres://user:pass@db/app ${stripe}`,
      registry,
    );

    assert.equal(
      result.text,
      "COOKIE=<secret:COOKIE> CREDENTIAL=<secret:CREDENTIAL> DATABASE_URL=<secret:DATABASE_URL> <secret:STRIPE_SECRET_KEY>",
    );
    assert.equal(result.replacements, 4);
  });

  it("handles bearer tokens, URL passwords, JWTs, and private keys", () => {
    const registry = new SecretRegistry();
    const bearer = "opaque-token-value-123456789";
    const jwt = `eyJ${"a".repeat(12)}.${"b".repeat(12)}.${"c".repeat(12)}`;
    const privateKey =
      "-----BEGIN PRIVATE KEY-----\nabcdefghi123456789\n-----END PRIVATE KEY-----";
    const result = sanitizeText(
      `Authorization: Bearer ${bearer}\nhttps://user:password123@example.test\n${jwt}\n${privateKey}`,
      registry,
    );

    assert.ok(!result.text.includes(bearer));
    assert.ok(!result.text.includes("password123"));
    assert.ok(!result.text.includes(jwt));
    assert.ok(!result.text.includes("abcdefghi123456789"));
    assert.match(result.text, /<secret:AUTH_TOKEN>/);
    assert.match(result.text, /<secret:URL_PASSWORD>/);
    assert.match(result.text, /<secret:PRIVATE_KEY>/);
  });

  it("does not redact environment references, placeholders, or short values", () => {
    const registry = new SecretRegistry();
    const text =
      "API_KEY=$API_KEY TOKEN=$" +
      "{TOKEN} SECRET=<secret:SECRET> PASSWORD=short";
    assert.deepEqual(sanitizeText(text, registry), {
      text,
      replacements: 0,
      secrets: [],
    });
  });

  it("redacts preloaded high-confidence values wherever they appear", () => {
    const registry = new SecretRegistry();
    registry.preload({ SERVICE_API_KEY: "unstructured-value-987654321" });
    const result = sanitizeText(
      "credential: unstructured-value-987654321",
      registry,
    );
    assert.equal(result.text, "credential: <secret:SERVICE_API_KEY>");
  });

  it("keeps low-entropy secrets contextual instead of replacing ordinary prose", () => {
    const registry = new SecretRegistry();
    registry.preload({ PASSWORD: "production" });

    assert.equal(
      sanitizeText("Deploy to production safely.", registry).text,
      "Deploy to production safely.",
    );
    assert.equal(
      sanitizeText("PASSWORD=production", registry).text,
      "PASSWORD=<secret:PASSWORD>",
    );
    assert.equal(
      sanitizeText("production\n", registry).text,
      "<secret:PASSWORD>\n",
    );
  });

  it("does not promote a pasted low-entropy assignment to global matching", () => {
    const registry = new SecretRegistry();

    assert.equal(
      sanitizeText("PASSWORD=production", registry).text,
      "PASSWORD=<secret:PASSWORD>",
    );
    assert.equal(
      sanitizeText("Deploy to production safely.", registry).text,
      "Deploy to production safely.",
    );
  });
});
