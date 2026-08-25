// sources/index.js
// Registry of threat-intel sources. To add Shodan / urlscan / ZoomEye later,
// create sources/<name>.js exporting `search({ key, query, size })` that returns
// [{host, ip, port, link, title, body}], then register it here.
import * as urlscan from "./urlscan.js";
import * as zoomeye from "./zoomeye.js";
import * as threatfox from "./threatfox.js";

export const SOURCES = {
  urlscan: {
    label: "urlscan",
    keyEnv: "URLSCAN_KEY",
    defaultQuery: urlscan.DEFAULT_QUERY,
    search: urlscan.search,
  },
  zoomeye: {
    label: "ZoomEye",
    keyEnv: "ZOOMEYE_KEY",
    defaultQuery: zoomeye.DEFAULT_QUERY,
    search: zoomeye.search,
  },
  threatfox: {
    label: "ThreatFox",
    keyEnv: "ABUSECH_AUTH_KEY",
    defaultQuery: threatfox.DEFAULT_QUERY,
    search: threatfox.search,
  },
};

export function listSources() {
  return Object.entries(SOURCES).map(([id, s]) => ({
    id,
    label: s.label,
    defaultQuery: s.defaultQuery,
    configured: !!process.env[s.keyEnv],
  }));
}
