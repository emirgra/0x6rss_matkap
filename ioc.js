// ioc.js
// Extract Telegram bot tokens and chat ids from arbitrary text (a website body,
// a script, a config dump...). Source-agnostic: FOFA/Shodan/urlscan/ZoomEye all
// feed their result bodies through here.

// Bot token: <bot_id (6-12 digits)>:<35 chars of [A-Za-z0-9_-]>.
// Leading (?<!\d) only guards against matching the tail of a longer number;
// a letter prefix such as "bot" (api.telegram.org/bot<token>) must still match.
const TOKEN_RE = /(?<!\d)(\d{6,12}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])/g;

// chat_id near an explicit "chat_id" key (json/query/form), value may be
// negative for groups/channels (e.g. -1001234567890).
const CHAT_NEAR_RE = /chat_?id["'\s:=\]\[\)\(]{0,6}(-?\d{5,})/gi;

// Bare channel/supergroup ids like -100xxxxxxxxxx, as a fallback.
const CHAT_BARE_RE = /(?<![\d-])(-100\d{7,})(?![\d])/g;

function collect(re, text) {
  const out = [];
  let m;
  re.lastIndex = 0;
  while ((m = re.exec(text)) !== null) out.push({ value: m[1], index: m.index });
  return out;
}

function uniqueByValue(list) {
  return [...new Map(list.map((x) => [x.value, x])).values()];
}

export function extractTelegramIOCs(text) {
  if (!text || typeof text !== "string") {
    return { tokens: [], chatIds: [], pairs: [] };
  }

  const tokens = uniqueByValue(collect(TOKEN_RE, text));
  const chats = uniqueByValue([...collect(CHAT_NEAR_RE, text), ...collect(CHAT_BARE_RE, text)]);

  // Pair each token with the nearest chat id in the text.
  const pairs = tokens.map((t) => {
    let best = null;
    let bestDist = Infinity;
    for (const c of chats) {
      const d = Math.abs(c.index - t.index);
      if (d < bestDist) {
        bestDist = d;
        best = c;
      }
    }
    return { token: t.value, chatId: best ? best.value : null };
  });

  return {
    tokens: tokens.map((t) => t.value),
    chatIds: chats.map((c) => c.value),
    pairs,
  };
}
