import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const baseFetch = globalThis.fetch;

function installTelemetryRedirect(stubOrigin) {
  globalThis.fetch = (url, init) => {
    const target = String(url);
    if (stubOrigin && target.includes("agentreel.dev/api/cli/events")) {
      const redirectUrl = new URL(new URL(target).pathname, stubOrigin).href;
      return baseFetch(redirectUrl, init);
    }
    return baseFetch(url, init);
  };
}

const statusCode = Number(process.argv[2] ?? "200");
const home = process.argv[3] ?? mkdtempSync(join(tmpdir(), "agentreel-telemetry-cli-"));
const outPath = process.argv[4];
const keepState = process.argv[5] === "keep";

if (!keepState) {
  rmSync(join(home, ".agentreel"), { recursive: true, force: true });
}

const requests = [];
const server = createServer((req, res) => {
  const chunks = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    const raw = Buffer.concat(chunks).toString("utf8");
    if (raw) {
      requests.push(JSON.parse(raw));
    }
    res.writeHead(statusCode, { "content-type": "application/json" });
    res.end("{}");
  });
});

await new Promise((resolve) => {
  server.listen(0, "127.0.0.1", resolve);
});

const origin = `http://127.0.0.1:${(server.address()).port}`;
installTelemetryRedirect(origin);
process.env.HOME = home;
process.env.NODE_ENV = "production";
process.env.VITEST = "";
process.env.VITEST_WORKER_ID = "";
delete process.env.AGENTREEL_TELEMETRY;

process.argv = ["node", "agentreel", "--version"];

const cliDir = join(dirname(fileURLToPath(import.meta.url)), "../../dist");
await import(pathToFileURL(join(cliDir, "cli.js")).href);

const deadline = Date.now() + 3_000;
while (Date.now() < deadline && !requests.some((r) => r.event === "cli_first_run")) {
  await new Promise((resolve) => setTimeout(resolve, 25));
}

const telemetryPath = join(home, ".agentreel", "telemetry.json");
const telemetry = existsSync(telemetryPath)
  ? JSON.parse(readFileSync(telemetryPath, "utf8"))
  : null;

if (outPath) {
  writeFileSync(outPath, JSON.stringify({ requests, telemetry }) + "\n", "utf8");
} else {
  process.stdout.write(JSON.stringify({ requests, telemetry }) + "\n");
}

server.close();