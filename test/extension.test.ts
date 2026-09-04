import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import keyRemoverExtension from "../src/index.js";

function placeholder(envName: string): string {
  const openingBracket = "<";
  return `${openingBracket}secret:${envName}>`;
}

interface CommandCompletion {
  value: string;
  label: string;
  description?: string;
}

interface CommandDefinition {
  description: string;
  getArgumentCompletions?: (prefix: string) => CommandCompletion[] | null;
  handler: (args: string, ctx: unknown) => Promise<void>;
}

interface Harness {
  handlers: Map<string, Array<(...args: unknown[]) => unknown>>;
  commands: Map<string, CommandDefinition>;
  tools: Map<
    string,
    {
      execute: (
        ...args: unknown[]
      ) => Promise<{ content: Array<{ type: string; text: string }> }>;
    }
  >;
  entries: Array<{ type: string; data: unknown }>;
}

function createHarness(): Harness & { pi: unknown } {
  const handlers = new Map<string, Array<(...args: unknown[]) => unknown>>();
  const commands = new Map<string, CommandDefinition>();
  const tools = new Map<
    string,
    {
      execute: (
        ...args: unknown[]
      ) => Promise<{ content: Array<{ type: string; text: string }> }>;
    }
  >();
  const entries: Array<{ type: string; data: unknown }> = [];
  const pi = {
    on(name: string, handler: (...args: unknown[]) => unknown) {
      handlers.set(name, [...(handlers.get(name) ?? []), handler]);
    },
    registerCommand(name: string, command: CommandDefinition) {
      commands.set(name, command);
    },
    registerTool(tool: {
      name: string;
      execute: (
        ...args: unknown[]
      ) => Promise<{ content: Array<{ type: string; text: string }> }>;
    }) {
      tools.set(tool.name, tool);
    },
    appendEntry(type: string, data: unknown) {
      entries.push({ type, data });
    },
  };
  return { handlers, commands, tools, entries, pi };
}

function createContext(cwd: string) {
  const notifications: string[] = [];
  const statuses: string[] = [];
  return {
    cwd,
    hasUI: true,
    isProjectTrusted: () => true,
    sessionManager: { getBranch: () => [] },
    ui: {
      notify(message: string) {
        notifications.push(message);
      },
      async confirm() {
        return true;
      },
      setStatus(_id: string, value: string | undefined) {
        if (value) statuses.push(value);
      },
    },
    notifications,
    statuses,
  };
}

async function invoke(
  harness: Harness,
  name: string,
  event: unknown,
  ctx: unknown,
): Promise<unknown> {
  const handlers = harness.handlers.get(name) ?? [];
  let result: unknown;
  for (const handler of handlers) result = await handler(event, ctx);
  return result;
}

describe("pi-key-remover extension", () => {
  it("sanitizes input/context, supports toggling, and executes with env-backed secrets", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "pi-key-remover-extension-"));
    await mkdir(join(cwd, ".pi"));
    await writeFile(
      join(cwd, ".pi", "key-remover.json"),
      JSON.stringify({ capturePastedSecrets: false, envFiles: [".env"] }),
    );
    const serviceSecret = "service-secret-value-123456789";
    const opaqueSecret = "selected-opaque-credential-123456";
    await writeFile(
      join(cwd, ".env"),
      `SERVICE_API_KEY=${serviceSecret}\nOPAQUE_NAME=${opaqueSecret}\n`,
    );

    const harness = createHarness();
    keyRemoverExtension(harness.pi as never);
    const ctx = createContext(cwd);
    await invoke(harness, "session_start", { reason: "startup" }, ctx);

    const pastedOpenAiKey = `sk-proj-${"Q7w8E9r0".repeat(5)}`;
    const openAiInput = (await invoke(
      harness,
      "input",
      {
        text: `my api key is: ${pastedOpenAiKey}`,
        images: [],
        source: "interactive",
      },
      ctx,
    )) as { action: string; text: string };
    const stablePlaceholderText = `my api key is: ${placeholder("OPENAI_API_KEY")}`;
    assert.equal(openAiInput.text, stablePlaceholderText);

    const finalizedOpenAiMessage = (await invoke(
      harness,
      "message_end",
      {
        message: {
          role: "user",
          content: [{ type: "text", text: openAiInput.text }],
        },
      },
      ctx,
    )) as { message: { content: Array<{ text: string }> } };
    assert.equal(
      finalizedOpenAiMessage.message.content[0]?.text,
      stablePlaceholderText,
    );

    const openAiContext = (await invoke(
      harness,
      "context",
      { messages: [finalizedOpenAiMessage.message] },
      ctx,
    )) as { messages: Array<{ content: Array<{ text: string }> }> };
    assert.equal(
      openAiContext.messages[0]?.content[0]?.text,
      stablePlaceholderText,
    );

    const openAiPayload = (await invoke(
      harness,
      "before_provider_request",
      { payload: { messages: openAiContext.messages } },
      ctx,
    )) as { messages: Array<{ content: Array<{ text: string }> }> };
    assert.equal(
      openAiPayload.messages[0]?.content[0]?.text,
      stablePlaceholderText,
    );

    const execTool = harness.tools.get("secret_exec");
    assert.ok(execTool);
    const availabilityResult = await execTool.execute(
      "placeholder-idempotence",
      {
        command: 'test -n "$OPENAI_API_KEY"; printf available',
        secrets: ["OPENAI_API_KEY"],
        timeoutSeconds: 5,
      },
      undefined,
      undefined,
      ctx,
    );
    assert.equal(availabilityResult.content[0]?.text, "available");

    const pasted = `ghp_${"xY7".repeat(14)}`;
    const inputResult = (await invoke(
      harness,
      "input",
      { text: `DEPLOY_TOKEN=${pasted}`, images: [], source: "interactive" },
      ctx,
    )) as { action: string; text: string };
    assert.equal(inputResult.action, "transform");
    assert.equal(inputResult.text, "DEPLOY_TOKEN=<secret:DEPLOY_TOKEN>");
    assert.ok(!inputResult.text.includes(pasted));

    const expandedSecret = "template-expanded-secret-123456";
    const messageEndResult = (await invoke(
      harness,
      "message_end",
      {
        message: {
          role: "user",
          content: [
            { type: "text", text: `TEMPLATE_TOKEN=${expandedSecret}，继续。` },
          ],
        },
      },
      ctx,
    )) as { message: { content: Array<{ text: string }> } };
    assert.equal(
      messageEndResult.message.content[0]?.text,
      "TEMPLATE_TOKEN=<secret:TEMPLATE_TOKEN>，继续。",
    );

    const nestedMessageResult = (await invoke(
      harness,
      "message_end",
      {
        message: {
          role: "assistant",
          content: [{ type: "toolCall", arguments: { data: expandedSecret } }],
        },
      },
      ctx,
    )) as { message: { content: Array<{ arguments: { data: string } }> } };
    assert.equal(
      nestedMessageResult.message.content[0]?.arguments.data,
      "<secret:TEMPLATE_TOKEN>",
    );

    const opaqueThinkingBlocks = [
      {
        type: "thinking",
        thinking: serviceSecret,
        signature: "signed-thinking",
      },
      {
        type: "reasoning",
        text: serviceSecret,
        encrypted_content: "encrypted-reasoning",
      },
      {
        type: "redacted_thinking",
        text: serviceSecret,
      },
    ];
    const thinkingMessageResult = (await invoke(
      harness,
      "message_end",
      {
        message: {
          role: "assistant",
          content: [
            ...opaqueThinkingBlocks,
            { type: "text", text: serviceSecret },
          ],
        },
      },
      ctx,
    )) as { message: { content: Array<Record<string, unknown>> } };
    assert.deepEqual(
      thinkingMessageResult.message.content.slice(0, 3),
      opaqueThinkingBlocks,
    );
    assert.equal(
      thinkingMessageResult.message.content[3]?.text,
      "<secret:SERVICE_API_KEY>",
    );

    const providerPayloadResult = (await invoke(
      harness,
      "before_provider_request",
      {
        payload: {
          content: [
            ...opaqueThinkingBlocks,
            { type: "text", text: serviceSecret },
          ],
        },
      },
      ctx,
    )) as { content: Array<Record<string, unknown>> };
    assert.deepEqual(
      providerPayloadResult.content.slice(0, 3),
      opaqueThinkingBlocks,
    );
    assert.equal(
      providerPayloadResult.content[3]?.text,
      "<secret:SERVICE_API_KEY>",
    );

    const contextResult = (await invoke(
      harness,
      "context",
      {
        messages: [
          {
            role: "user",
            content: [
              {
                type: "image",
                source: { type: "base64", data: serviceSecret },
              },
              { type: "text", text: serviceSecret },
            ],
          },
        ],
      },
      ctx,
    )) as {
      messages: Array<{
        content: Array<{
          type: string;
          source?: { data: string };
          text?: string;
        }>;
      }>;
    };
    assert.equal(
      contextResult.messages[0]?.content[0]?.source?.data,
      serviceSecret,
    );
    assert.equal(
      contextResult.messages[0]?.content[1]?.text,
      "<secret:SERVICE_API_KEY>",
    );

    const command = harness.commands.get("key-remover");
    assert.ok(command);
    assert.equal(harness.commands.has("kr"), false);
    assert.deepEqual(command.getArgumentCompletions?.(""), [
      {
        value: "toggle",
        label: "toggle",
        description: "Toggle key protection",
      },
      {
        value: "capture",
        label: "capture",
        description: "Toggle pasted-secret capture",
      },
      { value: "status", label: "status", description: "Show current status" },
      {
        value: "reload",
        label: "reload",
        description: "Reload configuration and secrets",
      },
    ]);
    assert.deepEqual(command.getArgumentCompletions?.("c"), [
      {
        value: "capture",
        label: "capture",
        description: "Toggle pasted-secret capture",
      },
    ]);
    assert.equal(command.getArgumentCompletions?.("unknown"), null);
    assert.equal(command.getArgumentCompletions?.("capture "), null);

    await command.handler("toggle", ctx);
    assert.deepEqual(await invoke(harness, "input", { text: pasted }, ctx), {
      action: "continue",
    });
    await command.handler("toggle", ctx);
    await command.handler("capture", ctx);
    assert.deepEqual(harness.entries.at(-1)?.data, {
      enabled: true,
      capturePastedSecrets: true,
    });
    const entryCount = harness.entries.length;
    await command.handler("on", ctx);
    await command.handler("capture on", ctx);
    assert.equal(harness.entries.length, entryCount);
    assert.equal(
      ctx.notifications.at(-1),
      "Usage: /key-remover [toggle|capture|status|reload]",
    );

    const tool = harness.tools.get("secret_exec");
    assert.ok(tool);
    const originalUnrequested = process.env.CI_JOB_JWT;
    process.env.CI_JOB_JWT = "must-not-be-inherited-123456";
    let toolResult: Awaited<ReturnType<typeof tool.execute>>;
    try {
      toolResult = await tool.execute(
        "call-1",
        {
          command:
            'printf \'%s|%s|%s|%s|%s\' "$SERVICE_API_KEY" "$DEPLOY_TOKEN" "$TEMPLATE_TOKEN" "$OPAQUE_NAME" "${CI_JOB_JWT-unset}"',
          secrets: [
            "SERVICE_API_KEY",
            "DEPLOY_TOKEN",
            "TEMPLATE_TOKEN",
            "OPAQUE_NAME",
          ],
          timeoutSeconds: 5,
        },
        undefined,
        undefined,
        ctx,
      );
    } finally {
      if (originalUnrequested === undefined) delete process.env.CI_JOB_JWT;
      else process.env.CI_JOB_JWT = originalUnrequested;
    }
    assert.equal(
      toolResult.content[0]?.text,
      "<secret:SERVICE_API_KEY>|<secret:DEPLOY_TOKEN>|<secret:TEMPLATE_TOKEN>|<secret:OPAQUE_NAME>|unset",
    );
    assert.ok(!toolResult.content[0]?.text.includes(serviceSecret));
    assert.ok(!toolResult.content[0]?.text.includes(pasted));
    assert.ok(!toolResult.content[0]?.text.includes(expandedSecret));
    assert.ok(!toolResult.content[0]?.text.includes(opaqueSecret));
    assert.ok(ctx.statuses.includes("keys: protected"));
  });
});
