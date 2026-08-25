// sources/zoomeye.js
// ZoomEye search client. Returns normalized results: {host, ip, port, link, title, body}.
// Note: the `body` (HTML body) field requires a ZoomEye Business plan; without it
// only header/banner are returned, which rarely carry the token.
import fetch from "node-fetch";

const BASE = "https://api.zoomeye.ai";

// Web assets whose HTML body references the Telegram Bot API.
export const DEFAULT_QUERY = 'http.body="api.telegram.org"';

export async function search({ key, query = DEFAULT_QUERY, size = 100 }) {
  if (!key) throw new Error("ZOOMEYE_KEY is not configured");

  const qbase64 = Buffer.from(query, "utf8").toString("base64");
  const resp = await fetch(`${BASE}/v2/search`, {
    method: "POST",
    headers: { "API-KEY": key, "Content-Type": "application/json" },
    body: JSON.stringify({
      qbase64,
      fields: "url,ip,port,domain,title,header,banner,body",
      pagesize: Math.min(size, 10000),
      page: 1,
    }),
  });

  const data = await resp.json();
  if (data.code !== 60000) {
    throw new Error(data.message || `ZoomEye error (code ${data.code})`);
  }

  const rows = data.data || [];
  return rows.map((r) => {
    const title = Array.isArray(r.title) ? r.title.join(" ") : r.title || null;
    const body = [r.header, r.banner, r.body].filter(Boolean).join("\n");
    const host = r.domain || r.ip || null;
    let link = r.url || null;
    if (!link && r.ip) {
      const scheme = r.port === 443 ? "https" : "http";
      link = `${scheme}://${host}` + (r.port === 80 || r.port === 443 ? "" : `:${r.port}`);
    }
    return {
      host,
      ip: r.ip || null,
      port: r.port || null,
      link,
      title,
      date: r.update_time || null,
      body,
    };
  });
}
