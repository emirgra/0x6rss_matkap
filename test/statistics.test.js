import assert from "node:assert/strict";
import test from "node:test";
import { buildThreatStatistics } from "../statistics.js";

test("threat statistics aggregate 7/14/30 day malware, report, and feed data", () => {
  const stats = buildThreatStatistics({
    days: 14,
    now: new Date("2026-08-25T12:00:00Z"),
    malwareSamples: [
      { first_seen: "2026-08-25 01:00:00", file_type: "exe", file_name: "a.exe", signature: "AgentTesla", campaigns: ["Summer Run"] },
      { first_seen: "2026-08-20 01:00:00", file_type: "exe", file_name: "b.exe", signature: "AgentTesla", campaigns: [] },
      { first_seen: "2026-07-01 01:00:00", file_type: "js", file_name: "old.js", signature: "OldFamily", campaigns: [] },
    ],
    reports: [
      { published_at: "2026-08-24T10:00:00Z", source: "example.test" },
      { published_at: null, source: "undated.test" },
    ],
    feedItems: [{ date: "2026-08-23T10:00:00Z", tags: ["telegram", "rat"] }],
  });

  assert.equal(stats.days, 14);
  assert.deepEqual(stats.summary, { malware: 2, reports: 1, feed: 1, families: 1, campaigns: 1 });
  assert.deepEqual(stats.dimensions.types, [{ label: "exe", count: 2 }]);
  assert.deepEqual(stats.dimensions.families, [{ label: "AgentTesla", count: 2 }]);
  assert.deepEqual(stats.dimensions.campaigns, [{ label: "Summer Run", count: 1 }]);
  assert.deepEqual(stats.dimensions.report_sources, [{ label: "example.test", count: 1 }]);
  assert.equal(stats.timeline.length, 14);
  assert.equal(stats.timeline.find((day) => day.date === "2026-08-25").malware, 1);
  assert.equal(stats.coverage.reports_without_date, 1);
});
