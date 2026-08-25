import crypto from "node:crypto";

const TOKEN_PATTERN = /(?<!\d)(\d{6,12}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])/g;
const CHAT_NEAR_PATTERN = /chat_?id["'\s:=\]\[\)\(]{0,8}(-?\d{5,})/gi;
// Bare channel/supergroup ids use Telegram's -100 prefix and are longer than a
// signed 32-bit Java hash. Shorter ids are accepted only beside a chat_id label.
const CHAT_BARE_PATTERN = /(?<![\d-])(-100\d{9,})(?![\d])/g;
function collect(pattern, text) {
  const matches = [];
  pattern.lastIndex = 0;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    matches.push({ value: match[1], index: match.index });
  }
  return matches;
}

function lineAndColumn(text, index) {
  const before = text.slice(0, index);
  const lines = before.split(/\r?\n/);
  return { line: lines.length, column: lines[lines.length - 1].length + 1 };
}

function maskToken(token) {
  const [id, secret = ""] = token.split(":");
  return `${id}:${secret.slice(0, 4)}…${secret.slice(-4)}`;
}

export function maskCredentialText(text) {
  TOKEN_PATTERN.lastIndex = 0;
  return text.replace(TOKEN_PATTERN, (_, token) => maskToken(token));
}

function contextAround(text, index, valueLength) {
  const start = Math.max(0, index - 140);
  const end = Math.min(text.length, index + valueLength + 140);
  return maskCredentialText(text.slice(start, end).replace(/[\r\n\t]+/g, " ").trim());
}

function findingId(kind, value, source, artifact) {
  return crypto
    .createHash("sha256")
    .update(`${kind}\0${value}\0${source}\0${artifact}`)
    .digest("hex")
    .slice(0, 24);
}

function nearestChat(token, chats) {
  let best = null;
  let distance = Number.POSITIVE_INFINITY;
  for (const chat of chats) {
    const current = Math.abs(token.index - chat.index);
    if (current < distance) {
      best = chat;
      distance = current;
    }
  }
  return distance <= 3000 ? best : null;
}

export function scanText(text, options = {}) {
  if (typeof text !== "string" || !text) return [];
  const source = options.source || "unknown";
  const artifact = options.artifact || "inline";
  const tokens = collect(TOKEN_PATTERN, text);
  const chats = [...collect(CHAT_NEAR_PATTERN, text), ...collect(CHAT_BARE_PATTERN, text)];
  const uniqueChats = [...new Map(chats.map((item) => [item.value, item])).values()];
  const findings = [];

  for (const token of tokens) {
    const location = lineAndColumn(text, token.index);
    const pairedChat = nearestChat(token, uniqueChats);
    findings.push({
      id: findingId("bot_token", token.value, source, artifact),
      kind: "bot_token",
      value: token.value,
      maskedValue: maskToken(token.value),
      chatId: pairedChat?.value || null,
      source,
      artifact,
      locator: { ...location, offset: token.index },
      context: contextAround(text, token.index, token.value.length),
      confidence: pairedChat ? 0.98 : 0.94,
      detectedAt: new Date().toISOString(),
    });
  }

  for (const chat of uniqueChats) {
    const location = lineAndColumn(text, chat.index);
    findings.push({
      id: findingId("chat_id", chat.value, source, artifact),
      kind: "chat_id",
      value: chat.value,
      maskedValue: chat.value,
      chatId: chat.value,
      source,
      artifact,
      locator: { ...location, offset: chat.index },
      context: contextAround(text, chat.index, chat.value.length),
      confidence: 0.9,
      detectedAt: new Date().toISOString(),
    });
  }

  return [...new Map(findings.map((item) => [item.id, item])).values()];
}
