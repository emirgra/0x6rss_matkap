import assert from "node:assert/strict";
import test from "node:test";
import { isSafeReadOnlyTool, runMcpInvestigation } from "../ai/mcp-agent.js";
import { scanText } from "../mcp/lib/telegram-scanner.js";
import { clearFindings, ingestFindings, listPublicFindings, revealFinding } from "../mcp/findings-store.js";
import { createToolHub } from "../mcp/tool-hub.js";
import { connectJadxRest } from "../mcp/jadx-rest-adapter.js";

const syntheticToken = `123456789:${"A".repeat(35)}`;

test("scanner pairs a Telegram token with its nearest chat id", () => {
  const findings = scanText(
    `https://api.telegram.org/bot${syntheticToken}/sendMessage?chat_id=-1001234567890`,
    { source: "test", artifact: "fixture" }
  );
  const token = findings.find((item) => item.kind === "bot_token");
  assert.equal(token.chatId, "-1001234567890");
  assert.ok(!token.maskedValue.includes("A".repeat(20)));
});

test("scanner does not treat a Java switch hash as a bare Telegram chat id", () => {
  const findings = scanText('case -1001078227: if (str.equals("progress")) break;', {
    source: "test",
    artifact: "MotionConstrainedPoint.java",
  });
  assert.equal(findings.length, 0);
});

test("public finding fields mask credentials outside the value field", () => {
  clearFindings();
  ingestFindings({
    source: "test",
    artifact: `https://api.telegram.org/bot${syntheticToken}/sendMessage`,
    findings: [{ kind: "bot_token", value: syntheticToken, context: `token=${syntheticToken}` }],
    metadata: { note: syntheticToken },
  });
  const listed = listPublicFindings();
  assert.ok(!JSON.stringify(listed).includes(syntheticToken));
  assert.equal(revealFinding(listed[0].id).value, syntheticToken);
  clearFindings();
});

test("MCP agent exposes only read-only reverse-engineering tools", () => {
  assert.equal(isSafeReadOnlyTool({ name: "decompile_function", annotations: { readOnlyHint: true } }), true);
  assert.equal(isSafeReadOnlyTool({ name: "patch_bytes", annotations: { readOnlyHint: true } }), false);
  assert.equal(isSafeReadOnlyTool({ name: "run_debugger" }), false);
  assert.equal(isSafeReadOnlyTool({ name: "read_file", annotations: { readOnlyHint: true } }), false);
});

test("AI agent drives a connected tool and validates exact Telegram artifacts", async () => {
  let providerCalls = 0;
  const toolCalls = [];
  const result = await runMcpInvestigation({
    provider: "anthropic",
    env: { MATKAP_MCP_AGENT_MAX_STEPS: "1", MATKAP_MCP_AGENT_MAX_CALLS: "4" },
    servers: [{
      id: "jadx",
      label: "JADX MCP",
      tools: [{
        name: "search_all_sources",
        description: "Search every decompiled source file",
        annotations: { readOnlyHint: true },
        inputSchema: { type: "object", properties: { query: { type: "string" } } },
      }],
      async callTool(name, args) {
        toolCalls.push({ name, args });
        return {
          content: [{
            type: "text",
            text: `https://api.telegram.org/bot${syntheticToken}/sendMessage?chat_id=-1001234567890`,
          }],
        };
      },
    }],
  }, {
    async generateProviderJson() {
      providerCalls++;
      if (providerCalls === 1) {
        return {
          model: "fixture-model",
          parsed: {
            summary: "Search project sources",
            done: false,
            actions: [{
              server: "jadx",
              tool: "search_all_sources",
              arguments_json: JSON.stringify({ query: "api.telegram.org" }),
              purpose: "Find Telegram API use",
            }],
            candidates: [],
          },
        };
      }
      return {
        model: "fixture-model",
        parsed: { summary: "Finished", done: true, actions: [], candidates: [] },
      };
    },
  });

  assert.equal(toolCalls.length, 1);
  assert.equal(result.calls.length, 1);
  assert.ok(result.findings.some((item) => item.kind === "bot_token" && item.value === syntheticToken));
  assert.ok(result.findings.some((item) => item.kind === "chat_id" && item.value === "-1001234567890"));
});

test("JADX preflight finds resource credentials without calling the AI provider", async () => {
  let providerCalls = 0;
  const result = await runMcpInvestigation({
    provider: "anthropic",
    servers: [{
      id: "jadx",
      label: "JADX MCP",
      tools: [
        { name: "get_all_resource_file_names", annotations: { readOnlyHint: true } },
        { name: "get_resource_file", annotations: { readOnlyHint: true } },
      ],
      async callTool(name, args) {
        if (name === "get_all_resource_file_names") {
          return { structuredContent: { files: ["assets/token.txt", "assets/chatid.txt"] }, content: [] };
        }
        const content = args.resource_name.includes("token") ? syntheticToken : "785008239";
        return {
          structuredContent: { type: "resource/text", file: { file_name: args.resource_name, content } },
          content: [{ type: "text", text: JSON.stringify({ file: { content } }) }],
        };
      },
    }],
  }, {
    async generateProviderJson() {
      providerCalls++;
      throw new Error("provider should not be called");
    },
  });

  assert.equal(providerCalls, 0);
  assert.equal(result.model, null);
  assert.ok(result.findings.some((item) => item.kind === "bot_token"));
  assert.ok(result.findings.some((item) => item.kind === "chat_id" && item.value === "785008239"));
});

test("JADX REST adapter exposes the GUI connector as read-only tools", async () => {
  const requests = [];
  const handle = await connectJadxRest({ url: "http://127.0.0.1:8650" }, {
    async fetchImpl(url) {
      requests.push(String(url));
      const data = url.pathname === "/health"
        ? { status: "Running" }
        : { type: "resource/text", file: { file_name: "assets/config.txt", content: "fixture" } };
      return { ok: true, status: 200, text: async () => JSON.stringify(data) };
    },
  });
  const tools = await handle.listTools();
  assert.ok(tools.every((tool) => tool.annotations.readOnlyHint));
  await handle.callTool("get_resource_file", { resource_name: "assets/config.txt" });
  assert.match(requests.at(-1), /get-resource-file\?file_name=assets%2Fconfig\.txt/);
});

test("local MCP preflight can finish without a configured provider", async () => {
  const result = await runMcpInvestigation({
    provider: null,
    servers: [{
      id: "jadx",
      label: "JADX MCP",
      tools: [{ name: "get_android_manifest", annotations: { readOnlyHint: true } }],
      async callTool() {
        return { content: [{ type: "text", text: "<manifest package=\"fixture\" />" }] };
      },
    }],
  }, {
    async generateProviderJson() {
      throw new Error("provider should not be called");
    },
  });
  assert.equal(result.provider, null);
  assert.equal(result.model, null);
  assert.deepEqual(result.findings, []);
});

test("tool hub tracks configured MCPs and completes one AI scan job", async () => {
  const closed = [];
  const published = [];
  const hub = createToolHub({
    env: {
      JADX_MCP_URL: "http://127.0.0.1:7101/mcp",
    },
    async connect(config) {
      return {
        transportKind: "streamable-http",
        async listTools() {
          return [{ name: "search_sources", annotations: { readOnlyHint: true } }];
        },
        async callTool() {
          return { content: [] };
        },
        async close() {
          closed.push(config.id);
        },
      };
    },
    async investigate({ servers, provider, onProgress }) {
      onProgress({ stage: "querying", progress: 60, message: "Reading connected tools" });
      return {
        provider,
        model: "fixture-model",
        summary: "Completed",
        servers: servers.map((server) => server.id),
        calls: servers.map((server) => ({ server: server.id, tool: "search_sources", ok: true })),
        findings: [{ kind: "bot_token", value: syntheticToken }],
        evidence: "masked fixture",
      };
    },
    async publishResult(result) {
      published.push(result);
      return { accepted: result.findings.length };
    },
  });

  const status = await hub.probeAll();
  assert.equal(status.filter((item) => item.connected).length, 1);
  assert.deepEqual(status.map((item) => item.name), ["jadx"]);

  const started = hub.startScan({ provider: "anthropic" });
  let job;
  const deadline = Date.now() + 2_000;
  do {
    await new Promise((resolve) => setTimeout(resolve, 10));
    job = hub.getJob(started.id);
  } while (!["completed", "error"].includes(job.status) && Date.now() < deadline);

  assert.equal(job.status, "completed");
  assert.equal(job.result.findings, 1);
  assert.deepEqual(job.result.servers, ["jadx"]);
  assert.equal(published.length, 1);
  await hub.close();
  assert.deepEqual(closed, ["jadx"]);
});

test("tool hub explains how to configure the packaged JADX connector", async () => {
  const hub = createToolHub({
    env: { JADX_MCP_URL: "http://127.0.0.1:8650/mcp" },
    async connect() {
      throw new Error("Endpoint POST /mcp not found (404)");
    },
    async publishResult() {
      return { accepted: 0 };
    },
  });
  const status = await hub.probeAll();
  assert.match(status.find((item) => item.name === "jadx").error, /8650.*jadx-rest/i);
});
