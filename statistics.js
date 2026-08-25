const DAY_MS = 24 * 60 * 60 * 1000;

function timestamp(value) {
  const text = String(value || "").trim();
  if (!text) return null;
  const parsed = Date.parse(text.includes("T") ? text : `${text.replace(" ", "T")}Z`);
  return Number.isFinite(parsed) ? parsed : null;
}

function calendarWindow(days, now) {
  const end = new Date(now);
  const endDay = Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate());
  return { start: endDay - (days - 1) * DAY_MS, end: endDay + DAY_MS - 1 };
}

function inWindow(value, window) {
  const time = timestamp(value);
  return time !== null && time >= window.start && time <= window.end;
}

function countValues(items, selector, limit = 10) {
  const counts = new Map();
  for (const item of items) {
    const selected = selector(item);
    const values = Array.isArray(selected) ? selected : [selected];
    for (const raw of values) {
      const label = String(raw || "").trim();
      if (!label) continue;
      const key = label.toLowerCase();
      const current = counts.get(key) || { label, count: 0 };
      current.count += 1;
      counts.set(key, current);
    }
  }
  return [...counts.values()]
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
    .slice(0, limit);
}

function dateKey(value) {
  const time = timestamp(value);
  return time === null ? null : new Date(time).toISOString().slice(0, 10);
}

export function filterSamplesByDays(samples, days, now = new Date()) {
  const safeDays = [7, 14, 30].includes(Number(days)) ? Number(days) : 14;
  const window = calendarWindow(safeDays, now);
  return (Array.isArray(samples) ? samples : []).filter((sample) => inWindow(sample.first_seen, window));
}

export function buildThreatStatistics({
  malwareSamples = [],
  reports = [],
  feedItems = [],
  days = 14,
  now = new Date(),
} = {}) {
  const safeDays = [7, 14, 30].includes(Number(days)) ? Number(days) : 14;
  const window = calendarWindow(safeDays, now);
  const malware = malwareSamples.filter((sample) => inWindow(sample.first_seen, window));
  const datedReports = reports.filter((report) => inWindow(report.published_at, window));
  const datedFeed = feedItems.filter((item) => inWindow(item.date, window));
  const allFamilies = countValues(malware, (sample) => sample.signature, Number.MAX_SAFE_INTEGER);
  const allCampaigns = countValues(malware, (sample) => sample.campaigns || [], Number.MAX_SAFE_INTEGER);
  const families = allFamilies.slice(0, 10);
  const campaigns = allCampaigns.slice(0, 10);

  const timelineMap = new Map();
  for (let offset = 0; offset < safeDays; offset += 1) {
    const date = new Date(window.start + offset * DAY_MS).toISOString().slice(0, 10);
    timelineMap.set(date, { date, malware: 0, reports: 0, feed: 0 });
  }
  for (const sample of malware) {
    const key = dateKey(sample.first_seen);
    if (timelineMap.has(key)) timelineMap.get(key).malware += 1;
  }
  for (const report of datedReports) {
    const key = dateKey(report.published_at);
    if (timelineMap.has(key)) timelineMap.get(key).reports += 1;
  }
  for (const item of datedFeed) {
    const key = dateKey(item.date);
    if (timelineMap.has(key)) timelineMap.get(key).feed += 1;
  }

  return {
    days: safeDays,
    generated_at: new Date(now).toISOString(),
    summary: {
      malware: malware.length,
      reports: datedReports.length,
      feed: datedFeed.length,
      families: allFamilies.length,
      campaigns: allCampaigns.length,
    },
    dimensions: {
      types: countValues(malware, (sample) => sample.file_type || sample.file_format || "unknown", 10),
      names: countValues(malware, (sample) => sample.file_name, 10),
      families,
      campaigns,
      report_sources: countValues(datedReports, (report) => report.source, 10),
      feed_tags: countValues(datedFeed, (item) => item.tags || [], 10),
    },
    timeline: [...timelineMap.values()],
    coverage: {
      malware_total_available: malwareSamples.length,
      reports_total_available: reports.length,
      reports_without_date: reports.filter((report) => !timestamp(report.published_at)).length,
      feed_total_available: feedItems.length,
      feed_without_date: feedItems.filter((item) => !timestamp(item.date)).length,
    },
  };
}
