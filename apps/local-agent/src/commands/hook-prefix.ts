// Pure choice of the command prefix written into Claude Code and Cursor
// hooks by `agentreel init`. Kept free of I/O so it is unit tested directly.

export const PACKAGE_NAME = "@agentreel/agent";

// A published npm version (X.Y.Z with an optional prerelease such as
// -alpha.1 or -beta.2). Build placeholders like "dev" or "test" do not match.
const PUBLISHED_VERSION_RE = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$/;

export type HookPrefixMode = "absolute" | "npx";

export interface HookPrefixInput {
  /** AGENTREEL_HOOK_COMMAND, when set. */
  hookCommandOverride?: string;
  /** True when the running CLI lives in an npx temp dir. */
  isEphemeral: boolean;
  /** Already shell-quoted absolute path to the running CLI. */
  quotedAbsolutePath: string;
  /** Version baked into the running CLI. */
  version: string;
}

/**
 * The npx hook prefix, pinned to the exact running version so a user who ran
 * `npx @agentreel/agent@beta init` keeps running that beta from their hooks
 * instead of drifting to whatever `latest` is later. Unpinned only for
 * unreleased builds whose version is not a published npm version.
 */
export function npxHookPrefix(version: string): string {
  return PUBLISHED_VERSION_RE.test(version)
    ? `npx -y ${PACKAGE_NAME}@${version}`
    : `npx -y ${PACKAGE_NAME}`;
}

export function chooseHookPrefix(input: HookPrefixInput): { prefix: string; mode: HookPrefixMode } {
  if (input.hookCommandOverride) {
    return { prefix: input.hookCommandOverride, mode: "absolute" };
  }
  if (input.isEphemeral) {
    return { prefix: npxHookPrefix(input.version), mode: "npx" };
  }
  return { prefix: input.quotedAbsolutePath, mode: "absolute" };
}
