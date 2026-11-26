#!/usr/bin/env node
// Validate a release locally or in CI. Never tags, pushes, or publishes.
//
// Local (run on a chore/release-* branch before merge):
//   pnpm release:check
//     Checks that apps/local-agent/package.json has an allowed version, that
//     CHANGELOG.md has its section and link, and that
//     .github/release-notes/v<version>.md exists and is not empty.
//
//   pnpm release:check --tag v0.3.0-beta.1 [--ref refs/tags/v0.3.0-beta.1]
//     Also checks the tag/version/channel rules the publish workflow applies.
//     Whether HEAD is on main is read from git (origin/main).
//
// CI (called by scripts/assert-publish-channel.sh):
//   node scripts/release-check.mjs --ci
//     Reads GITHUB_REF, TAGS_AT_HEAD (newline separated), ON_MAIN
//     ("true" or "false") and optional NPM_TAG from the environment and
//     writes channel, version and tag to GITHUB_OUTPUT.
//
// REPO_ROOT overrides the repo root (used by tests).
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { checkPublishChannel, checkReleaseFiles } from "./release-channel.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = process.env.REPO_ROOT ?? join(here, "..");

function parseArgs(argv) {
  const out = { ci: false, tag: undefined, ref: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--ci") out.ci = true;
    else if (a === "--tag") out.tag = argv[++i];
    else if (a === "--ref") out.ref = argv[++i];
    else throw new Error(`Unknown argument ${a}`);
  }
  return out;
}

function readText(path) {
  return existsSync(path) ? readFileSync(path, "utf8") : null;
}

function headIsOnMain() {
  try {
    execFileSync("git", ["merge-base", "--is-ancestor", "HEAD", "origin/main"], {
      cwd: repoRoot,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

function fail(errors) {
  for (const e of errors) console.error(`release-check: ${e}`);
  process.exit(1);
}

let args;
try {
  args = parseArgs(process.argv.slice(2));
} catch (err) {
  fail([err.message]);
}

const pkg = JSON.parse(readFileSync(join(repoRoot, "apps/local-agent/package.json"), "utf8"));
const version = pkg.version;
const notesRel = `.github/release-notes/v${version}.md`;

const errors = checkReleaseFiles({
  version,
  changelog: readText(join(repoRoot, "CHANGELOG.md")) ?? "",
  notes: readText(join(repoRoot, notesRel)),
  notesPath: notesRel,
});

let channelResult = null;
if (args.ci) {
  channelResult = checkPublishChannel({
    ref: process.env.GITHUB_REF ?? "",
    version,
    tagsAtHead: (process.env.TAGS_AT_HEAD ?? "").split("\n").map((t) => t.trim()).filter(Boolean),
    onMain: process.env.ON_MAIN === "true",
    npmTag: process.env.NPM_TAG,
  });
} else if (args.tag !== undefined || args.ref !== undefined) {
  channelResult = checkPublishChannel({
    ref: args.ref ?? `refs/tags/${args.tag}`,
    version,
    tagsAtHead: args.tag ? [args.tag] : [],
    onMain: headIsOnMain(),
  });
}
if (channelResult && !channelResult.ok) errors.push(...channelResult.errors);

if (errors.length > 0) fail(errors);

if (channelResult) {
  const { channel, tag } = channelResult;
  if (args.ci && process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `channel=${channel}\nversion=${version}\ntag=${tag}\n`);
  }
  console.log(`release-check ok: ${tag} publishes @agentreel/agent@${version} to dist-tag ${channel}`);
} else {
  console.log(`release-check ok: ${version} has its CHANGELOG section, link and ${notesRel}`);
}
