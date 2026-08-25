// sources/threatfox.js
// abuse.ch ThreatFox - community IOC database (same Auth-Key as MalwareBazaar).
// Telegram-bot C2 IOCs here are often the full api.telegram.org/bot<token> URL,
// so the shared parser pulls the token + chat_id straight out.
//
// Query field:
//   "api.telegram.org"  -> search_ioc (default)
//   "tag:telegram-c2"   -> taginfo for that tag
//   "malware:win.xxx"   -> malwareinfo for that family
import fetch from "node-fetch";

const URL = "https://threatfox-api.abuse.ch/api/v1/";

export const DEFAULT_QUERY = "api.telegram.org";

function buildPayload(query, size) {
  const limit = Math.min(size, 1000);
  if (query.startsWith("tag:")) return { query: "taginfo", tag: query.slice(4).trim(), limit };
  if (query.startsWith("malware:")) return { query: "malwareinfo", malware: query.slice(8).trim(), limit };
  return { query: "search_ioc", search_term: query };
}

export async function search({ key, query = DEFAULT_QUERY, size = 100 }) {
  if (!key) throw new Error("ThreatFox needs an abuse.ch Auth-Key (set ABUSECH_AUTH_KEY in .env).");

  const resp = await fetch(URL, {
    method: "POST",
    headers: { "Auth-Key": key, "Content-Type": "application/json" },
    body: JSON.stringify(buildPayload(query, size)),
  });
  if (resp.status === 401) throw new Error("ThreatFox auth failed (401) - check ABUSECH_AUTH_KEY.");

  const data = await resp.json().catch(() => ({}));
  if (data.query_status && data.query_status !== "ok") {
    if (/no_result|not_found|illegal_search_term/i.test(data.query_status)) return [];
    throw new Error(`ThreatFox: ${data.query_status}`);
  }

  const items = Array.isArray(data.data) ? data.data : [];
  return items.slice(0, size).map((it) => {
    const isUrl = /url/i.test(it.ioc_type || "");
    return {
      host: null,
      ip: /ip/i.test(it.ioc_type || "") ? String(it.ioc || "").split(":")[0] : null,
      port: null,
      link: isUrl ? it.ioc : null,
      title: it.malware_printable || it.malware || it.threat_type || null,
      date: it.first_seen || it.last_seen || null,
      // The IOC value carries the token URL; keep the record too for context.
      body: `${it.ioc || ""}\n${JSON.stringify(it)}`,
    };
  });
}
