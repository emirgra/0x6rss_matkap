import crypto from "node:crypto";
import { maskCredentialText } from "./lib/telegram-scanner.js";

const TOKEN_EXACT = /^\d{6,12}:[A-Za-z0-9_-]{35}$/;
const CHAT_EXACT = /^-?\d{5,}$/;
const findings = new Map();

function cleanText(value, max = 1000) {
  return String(value || "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").slice(0, max);
}

function maskToken(token) {
  const [id, secret = ""] = token.split(":");
  return `${id}:${secret.slice(0, 4)}…${secret.slice(-4)}`;
}

function canonicalId(kind, value, source, artifact) {
  return crypto
    .createHash("sha256")
    .update(`${kind}\0${value}\0${source}\0${artifact}`)
    .digest("hex")
    .slice(0, 24);
}

function correlationId(kind, value) {
  return crypto.createHash("sha256").update(`${kind}\0${value}`).digest("hex").slice(0, 16);
}

function validFinding(item) {
  if (!item || typeof item !== "object") return false;
  if (item.kind === "bot_token") return TOKEN_EXACT.test(String(item.value || ""));
  if (item.kind === "chat_id") return CHAT_EXACT.test(String(item.value || ""));
  return false;
}

export function ingestFindings({ source, artifact, findings: incoming = [] }) {
  const safeSource = maskCredentialText(cleanText(source, 80)) || "unknown";
  const safeArtifact = cleanText(artifact, 1000) || "unknown";
  let accepted = 0;

  for (const item of incoming.slice(0, 500)) {
    if (!validFinding(item)) continue;
    const value = String(item.value);
    const kind = item.kind;
    const id = canonicalId(kind, value, safeSource, safeArtifact);
    const previous = findings.get(id);
    findings.set(id, {
      id,
      correlationId: correlationId(kind, value),
      kind,
      value,
      maskedValue: kind === "bot_token" ? maskToken(value) : value,
      chatId: CHAT_EXACT.test(String(item.chatId || "")) ? String(item.chatId) : kind === "chat_id" ? value : null,
      source: safeSource,
      artifact: maskCredentialText(cleanText(item.artifact || safeArtifact, 1000)),
      locator: item.locator && typeof item.locator === "object" ? item.locator : {},
      context: maskCredentialText(cleanText(item.context, 800)),
      confidence: Math.max(0, Math.min(1, Number(item.confidence) || 0.5)),
      firstSeenAt: previous?.firstSeenAt || new Date().toISOString(),
      detectedAt: new Date().toISOString(),
      hits: (previous?.hits || 0) + 1,
    });
    accepted++;
  }

  return { accepted, total: findings.size };
}

export function listPublicFindings() {
  const groups = new Map();
  for (const finding of findings.values()) {
    const group = groups.get(finding.correlationId) || { sources: new Set(), detections: 0, items: [] };
    group.sources.add(finding.source);
    group.detections += finding.hits;
    group.items.push(finding);
    groups.set(finding.correlationId, group);
  }

  return [...groups.values()]
    .map((group) => {
      const primary = [...group.items].sort((a, b) => {
        const confidence = b.confidence - a.confidence;
        return confidence || b.detectedAt.localeCompare(a.detectedAt);
      })[0];
      const { value, ...item } = primary;
      const paired = group.items.find((candidate) => candidate.chatId)?.chatId || item.chatId;
      return {
        ...item,
        chatId: paired,
        correlation: {
          sources: [...group.sources].sort(),
          detections: group.detections || item.hits,
        },
      };
    })
    .sort((a, b) => b.detectedAt.localeCompare(a.detectedAt));
}

export function revealFinding(id) {
  const item = findings.get(String(id));
  if (!item) return null;
  return { id: item.id, kind: item.kind, value: item.value, chatId: item.chatId };
}

export function clearFindings() {
  const removed = findings.size;
  findings.clear();
  return removed;
}
