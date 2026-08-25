// news.js
// TI-report dorking: search reputable threat-intel sources for articles about
// Telegram-bot C2 / exfiltration, fetch the article, score it, and surface only
// the high-signal ones (score threshold keeps false positives out).
//
// URLs come from DuckDuckGo's HTML endpoint (free, no key). Article text is
// extracted from the HTML (no trafilatura on Node; a tag-strip is enough for
// keyword + context + entity extraction).
import fetch from "node-fetch";

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

// Expandable list of reputable threat-intel publishers.
export const NEWS_SOURCES = [
  "bleepingcomputer.com",
  "thehackernews.com",
  "group-ib.com",
  "welivesecurity.com",
  "securelist.com",
  "unit42.paloaltonetworks.com",
  "research.checkpoint.com",
  "blog.talosintelligence.com",
  "sentinelone.com",
  "trellix.com",
  "cyble.com",
  "zscaler.com",
  "news.sophos.com",
  "malwarebytes.com",
  "proofpoint.com",
  "fortinet.com",
  "trendmicro.com",
  "cisa.gov",
];

// Keyword weights. Score = sum of the weight of each DISTINCT keyword present.
const WEIGHTS = {
  "api.telegram.org": 10,
  sendmessage: 8,
  chat_id: 8,
  senddocument: 6,
  "telegram c2": 7,
  "telegram c&c": 7,
  "telegram exfiltration": 7,
  "bot token": 5,
  "telegram bot": 5,
  "telegram bots": 5,
  "t.me/": 4,
  telegram: 1,
};
export const KEYWORDS = Object.keys(WEIGHTS);

// Dorks kept to a few strong phrases so we don't fan out into too many searches.
const DORK_KEYWORDS = ["telegram bot", "api.telegram.org", "telegram c2"];

const TG_PATTERNS = {
  tme: /https?:\/\/t\.me\/[A-Za-z0-9_+/=?-]+/gi,
  username: /(?<!\w)@[A-Za-z0-9_]{4,32}/g,
  telegram_api: /https?:\/\/api\.telegram\.org\/[^\s"'<>]+/gi,
};

const MAX_DORKS = 24;
const MAX_ARTICLES = 40;
const FETCH_CONCURRENCY = 6;
const DEFAULT_MIN_SCORE = 8;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function decodeEntities(s) {
  return (s || "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)));
}

function extractText(html) {
  let h = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ");
  h = h.replace(/<\/(p|div|br|li|h[1-6]|section|article|tr)>/gi, "\n");
  h = h.replace(/<[^>]+>/g, " ");
  h = decodeEntities(h);
  return h.replace(/[ \t\f\v]+/g, " ").replace(/\n\s*\n+/g, "\n").trim();
}

function extractTitle(html) {
  const og = html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)/i);
  if (og) return decodeEntities(og[1]).trim();
  const t = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  return t ? decodeEntities(t[1]).trim() : null;
}

function extractDate(html) {
  const m = html.match(
    /<meta[^>]+(?:property|name)=["'](?:article:published_time|datePublished|publishdate|pubdate)["'][^>]+content=["']([^"']+)/i
  );
  return m ? m[1] : null;
}

function refang(s) {
  return (s || "")
    .replace(/\[\.\]|\(\.\)|\[dot\]/gi, ".")
    .replace(/\[:\]/g, ":")
    .replace(/h(?:xx|XX)(ps?)/gi, "htt$1");
}

// Extract IOCs an author actually flagged: defanged addresses (the [.] / hxxp
// markers are deliberate) plus file hashes. Staying defanged-only keeps the
// vendor's own links and boilerplate domains out.
function extractReportIOCs(text, html = "") {
  const ips = new Set();
  const domains = new Set();
  const urls = new Set();
  const hashes = new Set();

  // Defanged indicators are deliberate, so scanning the raw HTML (code blocks,
  // IOC tables, hrefs) is safe and catches more than the stripped text.
  const src = html || text;
  for (const m of src.matchAll(/\bh(?:xx|tt)ps?:(?:\/\/|\[:\]\/\/)[^\s"'<>)\]]+/gi)) {
    if (/hxx|\[\.\]|\[:\]/i.test(m[0])) urls.add(refang(m[0]));
  }
  for (const m of src.matchAll(/\b\d{1,3}(?:(?:\[\.\]|\.)\d{1,3}){3}\b/g)) {
    if (m[0].includes("[.]")) ips.add(refang(m[0]));
  }
  // Require an alphabetic TLD so fragments of defanged IPs (145[.]67) are skipped.
  for (const m of src.matchAll(/\b(?:[a-z0-9-]+(?:\[\.\][a-z0-9-]+)*\[\.\][a-z]{2,})\b/gi)) domains.add(refang(m[0]));
  // Hashes only from the readable text, to avoid HTML asset/etag hex false hits.
  for (const m of text.matchAll(/\b[a-f0-9]{64}\b/gi)) hashes.add(m[0].toLowerCase());
  for (const m of text.matchAll(/\b[a-f0-9]{40}\b/gi)) hashes.add(m[0].toLowerCase());
  for (const m of text.matchAll(/\b[a-f0-9]{32}\b/gi)) hashes.add(m[0].toLowerCase());

  return {
    ips: [...ips].slice(0, 40),
    domains: [...domains].slice(0, 40),
    urls: [...urls].slice(0, 40),
    hashes: [...hashes].slice(0, 40),
  };
}

function extractEntities(text) {
  const out = {};
  for (const [name, re] of Object.entries(TG_PATTERNS)) {
    out[name] = [...new Set((text.match(re) || []))].slice(0, 25);
  }
  return out;
}

function scoreArticle(text) {
  const lower = text.toLowerCase();
  let score = 0;
  const matchedKeywords = [];
  const contexts = [];

  for (const kw of KEYWORDS) {
    const pos = lower.indexOf(kw);
    if (pos === -1) continue;
    score += WEIGHTS[kw];
    matchedKeywords.push(kw);
    contexts.push({
      keyword: kw,
      context: text.slice(Math.max(0, pos - 200), pos + kw.length + 200).trim(),
    });
  }

  const entities = extractEntities(text);
  const botHandles = entities.username.filter((u) => /bot$/i.test(u));
  if (botHandles.length) score += 7;

  return { score, matchedKeywords, contexts, entities, botHandles };
}

async function fetchArticle(url) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    const resp = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": UA, Accept: "text/html" },
    });
    clearTimeout(timer);
    if (!resp.ok) return "";
    const buf = Buffer.from(await resp.arrayBuffer());
    return buf.slice(0, 1024 * 1024).toString("utf8");
  } catch (e) {
    return "";
  }
}

const UAS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
];
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function okPath(pathname) {
  return !/\/(tag|tags|category|categories|topic|topics|search|page|author)\//i.test(pathname);
}

function parseDdg(html, domain, limit) {
  const links = [...html.matchAll(/uddg=([^&"']+)/g)]
    .map((m) => {
      try {
        return decodeURIComponent(m[1]);
      } catch (e) {
        return null;
      }
    })
    .filter((u) => u && /^https?:\/\//i.test(u))
    .filter((u) => {
      try {
        const p = new URL(u);
        return p.hostname.endsWith(domain) && okPath(p.pathname);
      } catch (e) {
        return false;
      }
    });
  return [...new Set(links)].slice(0, limit);
}

// DuckDuckGo HTML search. Rotates UA and retries once on the 202 anti-bot page.
async function ddgSearch(query, domain, limit = 6) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const resp = await fetch(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`, {
        headers: { "User-Agent": UAS[attempt % UAS.length], Accept: "text/html", "Accept-Language": "en-US,en;q=0.9" },
      });
      if (resp.status === 200) {
        const html = await resp.text();
        const out = parseDdg(html, domain, limit);
        if (out.length || !/anomaly|challenge/i.test(html)) return out;
      }
      await wait(1300);
    } catch (e) {
      await wait(600);
    }
  }
  return [];
}

// Google Programmable Search (optional). Reliable, honors site:/quotes. Free
// 100 queries/day. Returns null when GOOGLE_CSE_KEY / GOOGLE_CSE_CX are unset.
async function cseSearch(query, domain, limit) {
  const key = process.env.GOOGLE_CSE_KEY;
  const cx = process.env.GOOGLE_CSE_CX;
  if (!key || !cx) return null;
  try {
    const url = `https://www.googleapis.com/customsearch/v1?key=${key}&cx=${cx}&num=10&q=${encodeURIComponent(query)}`;
    const resp = await fetch(url);
    const data = await resp.json();
    const items = data.items || [];
    const links = items
      .map((i) => i.link)
      .filter((u) => {
        try {
          const p = new URL(u);
          return p.hostname.endsWith(domain) && okPath(p.pathname);
        } catch (e) {
          return false;
        }
      });
    return [...new Set(links)].slice(0, limit);
  } catch (e) {
    return [];
  }
}

// Prefer Google CSE when configured, else fall back to DuckDuckGo.
async function searchDork(query, domain, limit) {
  const cse = await cseSearch(query, domain, limit);
  if (cse !== null) return cse;
  return ddgSearch(query, domain, limit);
}

export function generateDorks(sources, dorkKeywords) {
  const kws = dorkKeywords && dorkKeywords.length ? dorkKeywords : DORK_KEYWORDS;
  const dorks = [];
  for (const src of sources) {
    for (const kw of kws) {
      dorks.push({ source: src, keyword: kw, query: `site:${src} "${kw}"` });
    }
  }
  return dorks.slice(0, MAX_DORKS);
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return out;
}

export async function runNewsHunt({ sources, dorkKeywords, minScore = DEFAULT_MIN_SCORE, perDork = 6 } = {}) {
  const srcs = (sources && sources.length ? sources : NEWS_SOURCES).filter((s) => NEWS_SOURCES.includes(s));
  const dorks = generateDorks(srcs, dorkKeywords);

  // Collect candidate URLs (sequential DDG to stay under its rate limit).
  const urlToSource = new Map();
  for (const d of dorks) {
    const urls = await searchDork(d.query, d.source, perDork);
    for (const u of urls) if (!urlToSource.has(u)) urlToSource.set(u, d.source);
    if (urlToSource.size >= MAX_ARTICLES) break;
    await sleep(600);
  }

  const candidates = [...urlToSource.entries()].slice(0, MAX_ARTICLES);

  const analyzed = await mapLimit(candidates, FETCH_CONCURRENCY, async ([url, source]) => {
    const html = await fetchArticle(url);
    if (!html) return null;
    const text = extractText(html);
    if (!text) return null;
    const title = extractTitle(html);
    // Skip listing/tag pages that slipped through (e.g. "Latest Telegram news").
    if (title && /^latest .+ news$/i.test(title.trim())) return null;
    const { score, matchedKeywords, contexts, entities, botHandles } = scoreArticle(text);
    if (score < minScore) return null;
    return {
      url,
      source,
      title,
      published_at: extractDate(html),
      score,
      matchedKeywords,
      contexts: contexts.slice(0, 6),
      telegram: {
        handles: entities.username.filter((u) => /bot$/i.test(u)),
        tme: entities.tme,
        api: entities.telegram_api,
      },
      iocs: extractReportIOCs(text, html),
    };
  });

  const results = analyzed.filter(Boolean).sort((a, b) => b.score - a.score);

  return {
    sources: srcs.length,
    dorks: dorks.length,
    scanned: candidates.length,
    minScore,
    count: results.length,
    results,
  };
}
