// sources/urlscan.js
// urlscan.io search client. Returns normalized results: {host, ip, port, link, title, body}.
//
// Unlike FOFA/Shodan, urlscan search hits do not carry the page body. The bot
// token usually appears in a REQUEST the scanned page made, e.g.
// https://api.telegram.org/bot<token>/sendMessage?chat_id=<id>. Those URLs live
// in the scan result's `lists.urls`, so for each hit we fetch the result JSON
// and feed its URL list (plus the scanned URL) to the shared IOC parser.
import fetch from "node-fetch";

const BASE = "https://urlscan.io";

// Scans that contacted the Telegram Bot API domain.
export const DEFAULT_QUERY = "domain:api.telegram.org";

// Cap how many per-scan detail fetches we make (urlscan rate-limits bursts).
const DETAIL_CAP = 50;

export async function search({ key, query = DEFAULT_QUERY, size = 100 }) {
  if (!key) throw new Error("URLSCAN_KEY is not configured");

  const headers = { "api-key": key };
  const searchSize = Math.min(size, 100);
  const params = new URLSearchParams({ q: query, size: String(searchSize) });

  const resp = await fetch(`${BASE}/api/v1/search/?${params.toString()}`, { headers });
  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(data?.message || data?.description || `urlscan search failed (${resp.status})`);
  }

  const hits = data.results || [];
  const out = [];
  const limit = Math.min(hits.length, DETAIL_CAP);

  for (let i = 0; i < limit; i++) {
    const hit = hits[i];
    const scanId = hit._id;
    const bodyParts = [hit.task && hit.task.url, hit.page && hit.page.url].filter(Boolean);
    let title = null;

    try {
      const rResp = await fetch(`${BASE}/api/v1/result/${scanId}/`, { headers });
      if (rResp.ok) {
        const r = await rResp.json();
        title = (r.page && r.page.title) || null;
        const urls = (r.lists && r.lists.urls) || [];
        for (const u of urls) bodyParts.push(u);
      }
    } catch (e) {
      /* skip this scan's details */
    }

    // The captured request URLs carry the token (in the path) but usually not
    // the chat_id (it rides in the POST body). The phishing kit's inline config
    // - token AND chat_id - lives in the page DOM, so pull it for Telegram hits.
    const hasTg = bodyParts.some((u) => /api\.telegram\.org|t\.me\//i.test(u || ""));
    if (hasTg) {
      try {
        const domResp = await fetch(`${BASE}/dom/${scanId}/`, { headers });
        if (domResp.ok) {
          const dom = await domResp.text();
          bodyParts.push(dom.slice(0, 300000));
        }
      } catch (e) {
        /* dom optional */
      }
    }

    out.push({
      host: (hit.page && (hit.page.domain || hit.page.apexDomain)) || null,
      ip: (hit.page && hit.page.ip) || null,
      port: null,
      link: (hit.page && hit.page.url) || (hit.task && hit.task.url) || null,
      title,
      date: (hit.task && hit.task.time) || null,
      body: bodyParts.join("\n"),
    });
  }

  return out;
}
