import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const logPath = process.env.AGENTREEL_TELEMETRY_FETCH_LOG;
globalThis.fetch = (url, init) => {
  if (logPath) {
    mkdirSync(dirname(logPath), { recursive: true });
    appendFileSync(logPath, JSON.stringify({ url: String(url) }) + "\n", "utf8");
  }
  return Promise.resolve(new Response("{}", { status: 200 }));
};