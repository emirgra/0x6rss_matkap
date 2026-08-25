// tweetfeed.js
// tweetfeed.live - community IOCs shared on Twitter/X (free, no key).
//
// The TweetFeed API rows carry only the IOC value/tags + the tweet URL, NOT the
// tweet text. The keyword we care about ("telegram bot") lives in the tweet
// TEXT, so we group IOCs by tweet, fetch each tweet's text from X's public
// syndication endpoint (what the embed widget uses), and match keywords there.
import fetch from "node-fetch";
import { extractTelegramIOCs } from "./ioc.js";

const BASE = "https://api.tweetfeed.live/v1";
const VALID_TIME = new Set(["today", "week", "month"]);
const UA = "Mozilla/5.0 (compatible; MatkapIOC/1.0)";

// Telegram-bot-focused keywords, matched against the tweet text.
const DEFAULT_KEYWORDS = [
  "telegram bot",
  "telegram bots",
  "telegrambot",
  "api.telegram.org",
  "t.me/",
  "tg://",
  "bot token",
  "botfather",
];

const MAX_TWEETS = 200; // cap on per-tweet text fetches
const CONCURRENCY = 10;

// Cheap hint (no fetch): does this tweet's IOCs/tags look Telegram-related?
// Telegram-bot C2 tweets almost always carry a t.me / api.telegram.org IOC, so
// we fetch the text of these first to spend the budget where hits are likely.
function telegramHint(g) {
  const s = (g.iocs.map((i) => i.value).join(" ") + " " + [...g.tags].join(" ")).toLowerCase();
  return ["telegram", "t.me", "tg://"].some((k) => s.includes(k));
}

function tweetId(url) {
  const m = (url || "").match(/status\/(\d+)/);
  return m ? m[1] : null;
}

function synToken(id) {
  return ((Number(id) / 1e15) * Math.PI).toString(36).replace(/(0+|\.)/g, "");
}

async function fetchTweetText(id) {
  try {
    const url = `https://cdn.syndication.twimg.com/tweet-result?id=${id}&token=${synToken(id)}&lang=en`;
    const resp = await fetch(url, { headers: { "User-Agent": UA, Accept: "application/json" } });
    if (!resp.ok) return null;
    const j = await resp.json();
    return j && (j.text || j.full_text) ? j.text || j.full_text : null;
  } catch (e) {
    return null;
  }
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

export async function fetchTelegramThreats({ time = "week", keywords } = {}) {
  if (!VALID_TIME.has(time)) time = "week";
  const kws = (keywords && keywords.length ? keywords : DEFAULT_KEYWORDS).map((k) => k.toLowerCase());

  const resp = await fetch(`${BASE}/${time}`, { headers: { "User-Agent": UA, Accept: "application/json" } });
  if (!resp.ok) throw new Error(`tweetfeed error (${resp.status})`);
  const rows = await resp.json();
  const list = Array.isArray(rows) ? rows : [];

  // Group the IOCs by their source tweet.
  const byTweet = new Map();
  for (const r of list) {
    if (!r.tweet) continue;
    if (!byTweet.has(r.tweet)) {
      byTweet.set(r.tweet, { tweet: r.tweet, user: r.user, date: r.date, iocs: [], tags: new Set() });
    }
    const g = byTweet.get(r.tweet);
    if (r.value) g.iocs.push({ type: r.type, value: r.value });
    (r.tags || []).forEach((t) => g.tags.add(t));
  }

  // Prioritise likely-Telegram tweets, then fill remaining budget with the rest.
  const all = [...byTweet.values()];
  all.sort((a, b) => (telegramHint(b) ? 1 : 0) - (telegramHint(a) ? 1 : 0));
  const groups = all.slice(0, MAX_TWEETS);

  const texts = await mapLimit(groups, CONCURRENCY, async (g) => {
    const id = tweetId(g.tweet);
    return id ? await fetchTweetText(id) : null;
  });

  const results = [];
  groups.forEach((g, idx) => {
    const text = texts[idx] || "";
    const hay = text.toLowerCase();
    if (!text || !kws.some((k) => hay.includes(k))) return;

    const iocs = extractTelegramIOCs(text + "\n" + g.iocs.map((i) => i.value).join("\n"));
    results.push({
      tweet: g.tweet,
      user: g.user,
      date: g.date,
      text,
      tags: [...g.tags],
      iocs: g.iocs,
      tokens: iocs.tokens,
      chatIds: iocs.chatIds,
      pairs: iocs.pairs,
    });
  });

  return { window: time, totalTweets: byTweet.size, checked: groups.length, count: results.length, results };
}
