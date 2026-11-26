// Pure release-channel rules for @agentreel/agent.
//
// Every function here takes plain values and returns plain values. Nothing
// reads the filesystem, git, npm, or the environment, so the whole
// tag/version/channel matrix is unit tested in
// apps/local-agent/test/release-channel.test.ts. The I/O lives in
// scripts/release-check.mjs and scripts/assert-publish-channel.sh.

export const PACKAGE_NAME = "@agentreel/agent";

/** npm dist-tags this repo publishes to. */
export const CHANNELS = Object.freeze(["alpha", "beta", "latest"]);

export const MAIN_REF = "refs/heads/main";
const TAG_REF_PREFIX = "refs/tags/";

// X.Y.Z, X.Y.Z-alpha.N or X.Y.Z-beta.N. No leading zeros, N >= 1, no other
// prerelease ids (rc, next, canary) and no build metadata.
const RELEASE_VERSION_RE =
  /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(alpha|beta)\.([1-9][0-9]*))?$/;

/**
 * Parse a release version string.
 * @param {unknown} version
 * @returns {{ version: string, channel: "alpha" | "beta" | "latest", prerelease: number | null } | null}
 */
export function parseReleaseVersion(version) {
  if (typeof version !== "string") return null;
  const m = RELEASE_VERSION_RE.exec(version);
  if (!m) return null;
  const id = m[4];
  return {
    version,
    channel: id === "alpha" || id === "beta" ? id : "latest",
    prerelease: id ? Number(m[5]) : null,
  };
}

/**
 * Parse a release git tag. A release tag is a lowercase `v` followed by a
 * release version.
 * @param {unknown} tag
 */
export function parseReleaseTag(tag) {
  if (typeof tag !== "string" || !tag.startsWith("v")) return null;
  const parsed = parseReleaseVersion(tag.slice(1));
  return parsed ? { tag, ...parsed } : null;
}

/** The release tag for a version, for example `v0.3.0-beta.1`. */
export function tagForVersion(version) {
  return `v${version}`;
}

/**
 * Resolve which tag a publish run is for.
 *
 * A tag push (or a manual run started from a tag) uses that tag. A manual
 * run started from main uses the tag `v<version>` only if it points at the
 * checked-out commit. Any other ref is refused.
 *
 * @param {{ ref: string, version: string, tagsAtHead?: readonly string[] }} input
 * @returns {{ tag: string } | { error: string }}
 */
export function resolvePublishTag({ ref, version, tagsAtHead = [] }) {
  if (typeof ref === "string" && ref.startsWith(TAG_REF_PREFIX)) {
    return { tag: ref.slice(TAG_REF_PREFIX.length) };
  }
  if (ref === MAIN_REF) {
    const wanted = tagForVersion(version);
    if (tagsAtHead.includes(wanted)) return { tag: wanted };
    return { error: `Manual runs from main must be on a commit tagged ${wanted}` };
  }
  return { error: `Ref ${ref || "(empty)"} is not a release tag or ${MAIN_REF}; refusing to publish` };
}

/**
 * Decide whether a publish may run, and to which dist-tag.
 *
 * @param {{
 *   ref: string,
 *   version: string,
 *   tagsAtHead?: readonly string[],
 *   onMain: boolean,
 *   npmTag?: string,
 * }} input
 * @returns {{ ok: true, channel: string, version: string, tag: string } | { ok: false, errors: string[] }}
 */
export function checkPublishChannel({ ref, version, tagsAtHead = [], onMain, npmTag }) {
  const errors = [];

  const pkg = parseReleaseVersion(version);
  if (!pkg) {
    errors.push(
      `package.json version ${version} is not X.Y.Z, X.Y.Z-alpha.N or X.Y.Z-beta.N (N >= 1)`,
    );
  }

  const resolved = resolvePublishTag({ ref, version, tagsAtHead });
  const tag = "tag" in resolved ? resolved.tag : null;
  if ("error" in resolved) errors.push(resolved.error);

  const tagInfo = tag === null ? null : parseReleaseTag(tag);
  if (tag !== null && !tagInfo) {
    errors.push(`Tag ${tag} is not vX.Y.Z, vX.Y.Z-alpha.N or vX.Y.Z-beta.N (N >= 1)`);
  }
  if (tag !== null && tag !== tagForVersion(version)) {
    errors.push(`Tag ${tag} does not match package version ${tagForVersion(version)}`);
  }
  if (pkg && tagInfo && pkg.channel !== tagInfo.channel) {
    errors.push(`Tag ${tag} is on channel ${tagInfo.channel} but version ${version} is on channel ${pkg.channel}`);
  }

  if (onMain !== true) {
    errors.push("Commit is not on main; refusing to publish");
  }

  if (npmTag !== undefined && npmTag !== "" && pkg && npmTag !== pkg.channel) {
    errors.push(`npm dist-tag ${npmTag} does not match channel ${pkg.channel} for ${version}`);
  }

  if (errors.length > 0 || !pkg || tag === null) return { ok: false, errors };
  return { ok: true, channel: pkg.channel, version, tag };
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Check that a release has its changelog section, its changelog link, and a
 * non-empty GitHub release notes file.
 *
 * @param {{ version: string, changelog: string, notes: string | null, notesPath: string }} input
 * @returns {string[]} errors, empty when the release files are complete
 */
export function checkReleaseFiles({ version, changelog, notes, notesPath }) {
  const errors = [];
  if (!parseReleaseVersion(version)) {
    errors.push(
      `package.json version ${version} is not X.Y.Z, X.Y.Z-alpha.N or X.Y.Z-beta.N (N >= 1)`,
    );
    return errors;
  }
  const v = escapeRegExp(version);
  if (!new RegExp(`^## \\[${v}\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$`, "m").test(changelog)) {
    errors.push(`CHANGELOG.md is missing a '## [${version}] - YYYY-MM-DD' section`);
  }
  const link = new RegExp(
    `^\\[${v}\\]: https://github\\.com/agentreel/agent/(compare/v[^\\s]+\\.\\.\\.v${v}|releases/tag/v${v})$`,
    "m",
  );
  if (!link.test(changelog)) {
    errors.push(`CHANGELOG.md is missing a compare or release link for [${version}]`);
  }
  if (notes === null) {
    errors.push(`Missing GitHub release notes file ${notesPath}`);
  } else if (notes.trim() === "") {
    errors.push(`Release notes file ${notesPath} is empty`);
  }
  return errors;
}
