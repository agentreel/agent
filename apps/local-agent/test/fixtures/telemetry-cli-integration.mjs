import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const statusCode = Number(process.argv[2] ?? "200");
const home = process.argv[3] ?? mkdtempSync(join(tmpdir(), "agentreel-telemetry-cli-"));
const outPath = process.argv[4];
const keepState = process.argv[5] === "keep";
const cliArgs = process.argv.slice(6);
const argv = cliArgs.length > 0 ? cliArgs : ["--version"];
const delayMs = Number(process.env.AGENTREEL_TEST_STUB_DELAY_MS ?? "0");

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
    const respond = () => {
      res.writeHead(statusCode, { "content-type": "application/json" });
      res.end("{}");
    };
    if (delayMs > 0) {
      setTimeout(respond, delayMs);
    } else {
      respond();
    }
  });
});

await new Promise((resolve) => {
  server.listen(0, "127.0.0.1", resolve);
});

const address = server.address();
const origin = `http://127.0.0.1:${address.port}`;
const fixtureDir = dirname(fileURLToPath(import.meta.url));
const cliPath = join(fixtureDir, "../../dist/cli.js");
const redirectPreload = pathToFileURL(join(fixtureDir, "telemetry-cli-redirect.mjs")).href;

const childEnv = { ...process.env };
delete childEnv.AGENTREEL_TELEMETRY;
delete childEnv.DO_NOT_TRACK;
delete childEnv.CI;
delete childEnv.VITEST;
delete childEnv.VITEST_WORKER_ID;
delete childEnv.NODE_OPTIONS;
childEnv.HOME = home;
childEnv.NODE_ENV = "production";
childEnv.AGENTREEL_TEST_TELEMETRY_ORIGIN = origin;

const child = spawn(process.execPath, ["--import", redirectPreload, cliPath, ...argv], {
  env: childEnv,
  stdio: ["ignore", "pipe", "pipe"],
});

const exit = await new Promise((resolve, reject) => {
  child.once("error", reject);
  child.once("exit", (code, signal) => resolve({ code, signal }));
});

const expectZeroExit = argv.length === 1 && argv[0] === "--version";
if (exit.signal || (expectZeroExit && exit.code !== 0)) {
  throw new Error(
    `built CLI ${argv.join(" ")} exited with code ${exit.code} signal ${exit.signal}`,
  );
}

const telemetryPath = join(home, ".agentreel", "telemetry.json");
const telemetry = existsSync(telemetryPath)
  ? JSON.parse(readFileSync(telemetryPath, "utf8"))
  : null;

if (outPath) {
  writeFileSync(outPath, JSON.stringify({ requests, telemetry, exit }) + "\n", "utf8");
} else {
  process.stdout.write(JSON.stringify({ requests, telemetry, exit }) + "\n");
}

await new Promise((resolve, reject) => {
  server.close((err) => (err ? reject(err) : resolve()));
});
