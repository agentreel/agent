# Releasing @agentreel/agent

Releases are cut from git tags on `main`. There are no long-lived release branches, and nothing is ever published from a laptop.

## Channels

| Git tag | `package.json` version | npm dist-tag | GitHub release |
| --- | --- | --- | --- |
| `vX.Y.Z-alpha.N` | `X.Y.Z-alpha.N` | `alpha` | prerelease |
| `vX.Y.Z-beta.N` | `X.Y.Z-beta.N` | `beta` | prerelease |
| `vX.Y.Z` | `X.Y.Z` | `latest` | latest |

`N` starts at 1. No other prerelease ids (`rc`, `next`, `canary`) and no build metadata are allowed. Channels start on the 0.3.0 line: the first prerelease is `0.3.0-alpha.1` or `0.3.0-beta.1`.

## Cutting a release

1. Branch `chore/release-X.Y.Z-beta.N` (or `-alpha.N`, or plain `X.Y.Z`) from current `main`.
2. Set `apps/local-agent/package.json` `version` to that exact string.
3. Move the ready items from `## [Unreleased]` in `CHANGELOG.md` into `## [X.Y.Z-beta.N] - YYYY-MM-DD`, and add its compare link at the bottom (for example `[0.3.0-beta.1]: https://github.com/agentreel/agent/compare/v0.2.4...v0.3.0-beta.1`).
4. Write `.github/release-notes/vX.Y.Z-beta.N.md`. It becomes the GitHub release body.
5. Run `pnpm release:check`. It must pass.
6. Merge to `main` after review and Navjot's yes.
7. On the merge commit, run `pnpm release:check --tag vX.Y.Z-beta.N`, then push the annotated tag `vX.Y.Z-beta.N`.
8. The `publish` workflow waits for Navjot's approval on the `npm-publish` environment, publishes with `npm publish --tag <channel> --provenance`, then creates the GitHub release.
9. For a stable cut, also bump `CLI_VERSION` and `/changelog` on agentreel.dev so the site matches `latest`. The site stays on `latest` only.

## What the publish workflow refuses

`scripts/assert-publish-channel.sh` and `scripts/release-check.mjs` (rules in `scripts/release-channel.mjs`) fail the run before anything is published when:

- the tag is not `vX.Y.Z`, `vX.Y.Z-alpha.N` or `vX.Y.Z-beta.N`, or has no lowercase `v` prefix;
- the tag is not exactly `v` plus the `package.json` version, or their channels differ (a beta tag on an alpha version, a plain tag on a prerelease version);
- the run is not for a release tag, or is a manual run from a branch other than `main`, or a manual run from `main` whose commit does not carry the matching tag;
- the commit is not on `main`;
- the CHANGELOG section, its link, or the release notes file is missing;
- the version is already on npm.

## Promotion and rollback

npm versions are immutable, so promotion is always a new version: `0.3.0-beta.2` after `0.3.0-beta.1`, then `0.3.0` for `latest`. Never point `latest` at a prerelease.

To roll a channel back, Navjot moves the dist-tag onto an already published version of the same channel (`npm dist-tag add @agentreel/agent@<version> <channel>`) and deprecates the bad version (`npm deprecate`) rather than unpublishing. Users then re-run `init` from that channel so their hooks pin the rolled-back version.

## One-time setup (Navjot)

- Create the GitHub Environment `npm-publish` with himself as the required reviewer, and optionally restrict its deployment refs to tags matching `v*` (add `main` too if manual reruns from `main` should be allowed). Do this before the first release tag: GitHub creates a missing environment with no protection on first use.
- On npmjs.com, confirm the trusted publisher for `@agentreel/agent` still points at `agentreel/agent` and `.github/workflows/publish.yml`, with the environment field empty or `npm-publish`.
