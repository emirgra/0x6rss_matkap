import { AI_PROVIDER_IDS, listProviderStatus } from "./providers.js";

const TOKEN_EXACT = /^\d{6,12}:[A-Za-z0-9_-]{35}$/;
const CHAT_EXACT = /^-?\d{5,}$/;
const TOKEN_IN_TEXT = /(?<!\d)(\d{6,12}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])/;

function cleanText(value, max = 800) {
  return String(value || "").replace(/[\u0000-\u001f]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}

function maskTokens(text) {
  return cleanText(text, 1000).replace(
    /(?<!\d)(\d{6,12}):([A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])/g,
    (_, id, secret) => `${id}:${secret.slice(0, 4)}...${secret.slice(-4)}`
  );
}

function normalizedKind(candidate) {
  const kind = String(candidate?.kind || "").toLowerCase().replace(/[ -]/g, "_");
  if (["bot_token", "token", "telegram_bot_token"].includes(kind)) return "bot_token";
  if (["chat_id", "chatid", "telegram_chat_id"].includes(kind)) return "chat_id";
  return "";
}

function normalizedValue(kind, candidate) {
  const raw = String(candidate?.value ?? candidate?.token ?? candidate?.chat_id ?? "").trim();
  if (kind === "bot_token") {
    if (TOKEN_EXACT.test(raw)) return raw;
    const withoutBot = raw.replace(/^bot/i, "");
    if (TOKEN_EXACT.test(withoutBot)) return withoutBot;
    return raw.match(TOKEN_IN_TEXT)?.[1] || "";
  }
  const unquoted = raw.replace(/^["']|["']$/g, "");
  return CHAT_EXACT.test(unquoted) ? unquoted : "";
}

export function normalizeProviderFindings(result, evidence) {
  const candidates = Array.isArray(result?.parsed?.candidates) ? result.parsed.candidates : [];
  const accepted = [];
  const unique = new Set();
  for (const candidate of candidates.slice(0, 100)) {
    const kind = normalizedKind(candidate);
    const value = normalizedValue(kind, candidate);
    if (!kind || !value || unique.has(`${kind}\0${value}`)) continue;
    unique.add(`${kind}\0${value}`);
    accepted.push({
      kind,
      value,
      chatId: kind === "chat_id" ? value : null,
      source: `ai-${result.provider}`,
      artifact: evidence.artifact,
      locator: { provider: result.provider, model: result.model },
      context: maskTokens(candidate.evidence || candidate.reason || "AI-reconstructed candidate"),
      confidence: Math.min(0.95, Math.max(0.2, Number(candidate.confidence) || 0.65)),
    });
  }
  const chatIds = accepted.filter((item) => item.kind === "chat_id");
  if (chatIds.length === 1) {
    for (const item of accepted) if (item.kind === "bot_token") item.chatId = chatIds[0].value;
  }
  return accepted;
}

export function resolveProviders(requested, strategy = "single", env = process.env) {
  const configured = new Set(listProviderStatus(env).filter((item) => item.configured).map((item) => item.id));
  const supplied = Array.isArray(requested) ? requested : [];
  let selected = supplied.filter((id) => AI_PROVIDER_IDS.includes(id) && configured.has(id));
  if (!selected.length) {
    const primary = String(env.MATKAP_AI_PRIMARY || "openai").trim().toLowerCase();
    if (configured.has(primary)) selected = [primary];
    else selected = AI_PROVIDER_IDS.filter((id) => configured.has(id));
  }
  return strategy === "ensemble" ? selected : selected.slice(0, 1);
}
