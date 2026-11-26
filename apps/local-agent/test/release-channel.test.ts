import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import * as rc from "../../../scripts/release-channel.mjs";

const repoScripts = join(dirname(fileURLToPath(import.meta.url)), "../../../scripts");

const tagRef = (tag: string) => `refs/tags/${tag}`;

describe("parseReleaseVersion", () => {
  it.each([
    ["0.3.0", "latest", null],
    ["0.3.0-alpha.1", "alpha", 1],
    ["0.3.0-beta.1", "beta", 1],
    ["10.20.30-beta.42", "beta", 42],
  ])("accepts %s as %s", (version, channel, prerelease) => {
    expect(rc.parseReleaseVersion(version)).toEqual({ version, channel, prerelease });
  });

  it.each([
    "v0.3.0",
    "0.3",
    "0.3.0-rc.1",
    "0.3.0-next.1",
    "0.3.0-beta",
    "0.3.0-beta.0",
    "0.3.0-beta.01",
    "0.3.0-alpha.1.2",
    "01.3.0",
    "0.3.0+build.1",
    "0.3.0-BETA.1",
    " 0.3.0",
    "",
  ])("rejects %j", (version) => {
    expect(rc.parseReleaseVersion(version)).toBeNull();
  });

  it("rejects non-strings", () => {
    expect(rc.parseReleaseVersion(undefined)).toBeNull();
    expect(rc.parseReleaseVersion(3)).toBeNull();
  });
});

describe("parseReleaseTag", () => {
  it("needs a lowercase v prefix", () => {
    expect(rc.parseReleaseTag("v0.3.0-beta.1")).toMatchObject({ channel: "beta", version: "0.3.0-beta.1" });
    expect(rc.parseReleaseTag("0.3.0")).toBeNull();
    expect(rc.parseReleaseTag("V0.3.0")).toBeNull();
    expect(rc.parseReleaseTag("vv0.3.0")).toBeNull();
  });
});

describe("checkPublishChannel: good cases", () => {
  it.each([
    ["v0.3.0-alpha.1", "0.3.0-alpha.1", "alpha"],
    ["v0.3.0-beta.1", "0.3.0-beta.1", "beta"],
    ["v0.3.0", "0.3.0", "latest"],
  ])("tag %s with version %s publishes to %s", (tag, version, channel) => {
    expect(rc.checkPublishChannel({ ref: tagRef(tag), version, onMain: true })).toEqual({
      ok: true,
      channel,
      version,
      tag,
    });
  });

  it("allows a manual run from main when the matching tag points at HEAD", () => {
    expect(
      rc.checkPublishChannel({
        ref: "refs/heads/main",
        version: "0.3.0-beta.2",
        tagsAtHead: ["v0.3.0-beta.1", "v0.3.0-beta.2"],
        onMain: true,
      }),
    ).toMatchObject({ ok: true, channel: "beta", tag: "v0.3.0-beta.2" });
  });

  it("accepts an explicit npm tag that matches the channel", () => {
    expect(
      rc.checkPublishChannel({ ref: tagRef("v0.3.0-alpha.3"), version: "0.3.0-alpha.3", onMain: true, npmTag: "alpha" }),
    ).toMatchObject({ ok: true, channel: "alpha" });
  });
});

describe("checkPublishChannel: bad cases", () => {
  const errorsOf = (input: Record<string, unknown>) => {
    const r = rc.checkPublishChannel({ onMain: true, ...input });
    expect(r.ok).toBe(false);
    return (r as { errors: string[] }).errors.join("\n");
  };

  it("refuses a beta tag on an alpha version", () => {
    const e = errorsOf({ ref: tagRef("v0.3.0-beta.1"), version: "0.3.0-alpha.1" });
    expect(e).toMatch(/does not match package version v0\.3\.0-alpha\.1/);
    expect(e).toMatch(/channel beta but version 0\.3\.0-alpha\.1 is on channel alpha/);
  });

  it("refuses an alpha tag on a beta version", () => {
    expect(errorsOf({ ref: tagRef("v0.3.0-alpha.1"), version: "0.3.0-beta.1" })).toMatch(/channel alpha/);
  });

  it("refuses a plain tag with a prerelease version (prerelease must never reach latest)", () => {
    const e = errorsOf({ ref: tagRef("v0.3.0"), version: "0.3.0-beta.1" });
    expect(e).toMatch(/channel latest but version 0\.3\.0-beta\.1 is on channel beta/);
  });

  it("refuses a prerelease tag on a stable version", () => {
    expect(errorsOf({ ref: tagRef("v0.3.0-beta.1"), version: "0.3.0" })).toMatch(/channel beta/);
  });

  it("refuses a tag without the v prefix", () => {
    const e = errorsOf({ ref: tagRef("0.3.0-beta.1"), version: "0.3.0-beta.1" });
    expect(e).toMatch(/Tag 0\.3\.0-beta\.1 is not vX\.Y\.Z/);
    expect(e).toMatch(/does not match package version/);
  });

  it("refuses an uppercase V prefix", () => {
    expect(errorsOf({ ref: tagRef("V0.3.0"), version: "0.3.0" })).toMatch(/Tag V0\.3\.0 is not vX\.Y\.Z/);
  });

  it("refuses a v prefix inside package.json", () => {
    expect(errorsOf({ ref: tagRef("vv0.3.0"), version: "v0.3.0" })).toMatch(/package\.json version v0\.3\.0 is not/);
  });

  it("refuses a different number on the same channel", () => {
    expect(errorsOf({ ref: tagRef("v0.3.0-beta.2"), version: "0.3.0-beta.1" })).toMatch(/does not match/);
  });

  it("refuses rc and other prerelease ids", () => {
    expect(errorsOf({ ref: tagRef("v0.3.0-rc.1"), version: "0.3.0-rc.1" })).toMatch(/is not X\.Y\.Z/);
  });

  it("refuses a manual run from a non-main branch", () => {
    expect(
      errorsOf({ ref: "refs/heads/feat/release-channels", version: "0.3.0-beta.1", tagsAtHead: ["v0.3.0-beta.1"] }),
    ).toMatch(/Ref refs\/heads\/feat\/release-channels is not a release tag or refs\/heads\/main/);
  });

  it("refuses a pull request ref", () => {
    expect(errorsOf({ ref: "refs/pull/19/merge", version: "0.3.0" })).toMatch(/not a release tag/);
  });

  it("refuses an empty ref", () => {
    expect(errorsOf({ ref: "", version: "0.3.0" })).toMatch(/\(empty\)/);
  });

  it("refuses a manual run from main when HEAD has no matching tag", () => {
    expect(
      errorsOf({ ref: "refs/heads/main", version: "0.3.0-beta.2", tagsAtHead: ["v0.3.0-beta.1"] }),
    ).toMatch(/must be on a commit tagged v0\.3\.0-beta\.2/);
  });

  it("refuses a correct tag whose commit is not on main", () => {
    const r = rc.checkPublishChannel({ ref: tagRef("v0.3.0-beta.1"), version: "0.3.0-beta.1", onMain: false });
    expect(r).toEqual({ ok: false, errors: ["Commit is not on main; refusing to publish"] });
  });

  it("refuses when onMain is unknown", () => {
    const r = rc.checkPublishChannel({ ref: tagRef("v0.3.0"), version: "0.3.0" });
    expect(r.ok).toBe(false);
  });

  it("refuses an npm tag that does not match the channel", () => {
    expect(errorsOf({ ref: tagRef("v0.3.0-beta.1"), version: "0.3.0-beta.1", npmTag: "latest" })).toMatch(
      /npm dist-tag latest does not match channel beta/,
    );
  });
});

const CHANGELOG = [
  "# Changelog",
  "",
  "## [Unreleased]",
  "",
  "## [0.3.0-beta.1] - 2026-12-01",
  "",
  "### Added",
  "",
  "- Something.",
  "",
  "[Unreleased]: https://github.com/agentreel/agent/compare/v0.3.0-beta.1...HEAD",
  "[0.3.0-beta.1]: https://github.com/agentreel/agent/compare/v0.2.4...v0.3.0-beta.1",
  "",
].join("\n");

describe("checkReleaseFiles", () => {
  const ok = { version: "0.3.0-beta.1", changelog: CHANGELOG, notes: "## Added\n\n- x\n", notesPath: "n.md" };

  it("passes a complete release", () => {
    expect(rc.checkReleaseFiles(ok)).toEqual([]);
  });

  it("needs the dated changelog section", () => {
    expect(rc.checkReleaseFiles({ ...ok, version: "0.3.0-beta.2" }).join("\n")).toMatch(/missing a '## \[0\.3\.0-beta\.2\]/);
    const undated = CHANGELOG.replace("## [0.3.0-beta.1] - 2026-12-01", "## [0.3.0-beta.1]");
    expect(rc.checkReleaseFiles({ ...ok, changelog: undated })).toHaveLength(1);
  });

  it("does not treat a longer version as the section (0.3.0 vs 0.3.0-beta.1)", () => {
    expect(rc.checkReleaseFiles({ ...ok, version: "0.3.0" }).join("\n")).toMatch(/missing a '## \[0\.3\.0\]/);
  });

  it("needs the compare link", () => {
    const noLink = CHANGELOG.replace(/^\[0\.3\.0-beta\.1\]:.*$/m, "");
    expect(rc.checkReleaseFiles({ ...ok, changelog: noLink })).toEqual([
      "CHANGELOG.md is missing a compare or release link for [0.3.0-beta.1]",
    ]);
  });

  it("needs a non-empty release notes file", () => {
    expect(rc.checkReleaseFiles({ ...ok, notes: null })).toEqual(["Missing GitHub release notes file n.md"]);
    expect(rc.checkReleaseFiles({ ...ok, notes: " \n" })).toEqual(["Release notes file n.md is empty"]);
  });

  it("rejects a disallowed version before looking at files", () => {
    expect(rc.checkReleaseFiles({ ...ok, version: "0.3.0-rc.1" })).toHaveLength(1);
  });
});

// End-to-end: the real scripts against a throwaway repo layout, with git and
// npm replaced by stubs so nothing touches the network or a real registry.
describe("release-check.mjs and assert-publish-channel.sh", () => {
  let root: string;
  afterEach(() => {
    if (root) rmSync(root, { recursive: true, force: true });
  });

  function fixture(version: string, { notes = true } = {}) {
    root = mkdtempSync(join(tmpdir(), "ar-release-"));
    mkdirSync(join(root, "scripts"));
    for (const f of ["release-channel.mjs", "release-check.mjs", "assert-publish-channel.sh"]) {
      copyFileSync(join(repoScripts, f), join(root, "scripts", f));
    }
    mkdirSync(join(root, "apps/local-agent"), { recursive: true });
    writeFileSync(join(root, "apps/local-agent/package.json"), JSON.stringify({ version }));
    writeFileSync(join(root, "CHANGELOG.md"), CHANGELOG.replaceAll("0.3.0-beta.1", version));
    mkdirSync(join(root, ".github/release-notes"), { recursive: true });
    if (notes) writeFileSync(join(root, `.github/release-notes/v${version}.md`), "## Added\n\n- x\n");
    const bin = join(root, "stub-bin");
    mkdirSync(bin);
    writeFileSync(
      join(bin, "git"),
      [
        "#!/usr/bin/env bash",
        'case "$1" in',
        "  fetch) exit 0 ;;",
        '  merge-base) [ "${STUB_ON_MAIN:-true}" = true ] ;;',
        '  tag) printf "%s\\n" ${STUB_TAGS:-} ;;',
        "  *) exit 2 ;;",
        "esac",
        "",
      ].join("\n"),
    );
    writeFileSync(
      join(bin, "npm"),
      ['#!/usr/bin/env bash', '[ "$1" = view ] && [ "${STUB_ON_NPM:-0}" = 1 ]', ""].join("\n"),
    );
    chmodSync(join(bin, "git"), 0o755);
    chmodSync(join(bin, "npm"), 0o755);
    return bin;
  }

  function runAssert(bin: string, env: Record<string, string>) {
    const out = join(root, "gh-output");
    writeFileSync(out, "");
    const r = spawnSync("bash", [join(root, "scripts/assert-publish-channel.sh")], {
      encoding: "utf8",
      env: { PATH: `${bin}:${process.env.PATH}`, GITHUB_OUTPUT: out, ...env },
    });
    return { status: r.status, stderr: r.stderr, output: readFileSync(out, "utf8") };
  }

  it("release-check passes locally on a complete release and names the files", () => {
    fixture("0.3.0-alpha.1");
    const r = spawnSync("node", [join(root, "scripts/release-check.mjs")], { encoding: "utf8", env: { ...process.env, REPO_ROOT: root } });
    expect(r.status).toBe(0);
    expect(r.stdout).toMatch(/0\.3\.0-alpha\.1 has its CHANGELOG section/);
  });

  it("release-check fails locally when release notes are missing", () => {
    fixture("0.3.0-alpha.1", { notes: false });
    const r = spawnSync("node", [join(root, "scripts/release-check.mjs")], { encoding: "utf8", env: { ...process.env, REPO_ROOT: root } });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/Missing GitHub release notes file \.github\/release-notes\/v0\.3\.0-alpha\.1\.md/);
  });

  it("release-check --tag refuses a mismatched tag locally", () => {
    fixture("0.3.0-alpha.1");
    const r = spawnSync("node", [join(root, "scripts/release-check.mjs"), "--tag", "v0.3.0-beta.1"], {
      encoding: "utf8",
      env: { ...process.env, REPO_ROOT: root },
    });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/does not match package version v0\.3\.0-alpha\.1/);
  });

  it("the publish guard writes the beta channel for a matching beta tag", () => {
    const bin = fixture("0.3.0-beta.1");
    const r = runAssert(bin, { GITHUB_REF: "refs/tags/v0.3.0-beta.1" });
    expect(r.stderr).toBe("");
    expect(r.status).toBe(0);
    expect(r.output).toBe("channel=beta\nversion=0.3.0-beta.1\ntag=v0.3.0-beta.1\n");
  });

  it("the publish guard writes latest for a stable tag from a manual run on main", () => {
    const bin = fixture("0.3.0");
    const r = runAssert(bin, { GITHUB_REF: "refs/heads/main", STUB_TAGS: "v0.3.0" });
    expect(r.status).toBe(0);
    expect(r.output).toMatch(/^channel=latest$/m);
  });

  it("the publish guard fails a plain tag on a prerelease version and writes no channel", () => {
    const bin = fixture("0.3.0-beta.1");
    const r = runAssert(bin, { GITHUB_REF: "refs/tags/v0.3.0" });
    expect(r.status).not.toBe(0);
    expect(r.output).toBe("");
  });

  it("the publish guard fails when the commit is not on main", () => {
    const bin = fixture("0.3.0-beta.1");
    const r = runAssert(bin, { GITHUB_REF: "refs/tags/v0.3.0-beta.1", STUB_ON_MAIN: "false" });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/Commit is not on main/);
  });

  it("the publish guard fails a manual run from a non-main branch", () => {
    const bin = fixture("0.3.0-beta.1");
    const r = runAssert(bin, { GITHUB_REF: "refs/heads/feat/x", STUB_TAGS: "v0.3.0-beta.1" });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/is not a release tag or refs\/heads\/main/);
  });

  it("the publish guard fails when the version is already on npm", () => {
    const bin = fixture("0.3.0-beta.1");
    const r = runAssert(bin, { GITHUB_REF: "refs/tags/v0.3.0-beta.1", STUB_ON_NPM: "1" });
    expect(r.status).not.toBe(0);
    expect(r.stderr).toMatch(/already on npm/);
  });
});
