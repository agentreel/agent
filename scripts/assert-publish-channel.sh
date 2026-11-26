#!/usr/bin/env bash
# Publish guard for .github/workflows/publish.yml. Never publishes.
#
# Gathers git and npm facts, then lets scripts/release-check.mjs decide
# whether the tag, apps/local-agent/package.json version and npm dist-tag
# agree. Fails if they do not, if the commit is not on main, or if the
# version is already on npm. Writes channel, version and tag to
# GITHUB_OUTPUT.
set -euo pipefail

cd "$(dirname "$0")/.."

git fetch --quiet --tags --force origin
git fetch --quiet origin main

if git merge-base --is-ancestor HEAD origin/main; then
  ON_MAIN=true
else
  ON_MAIN=false
fi
TAGS_AT_HEAD="$(git tag --points-at HEAD)"
export ON_MAIN TAGS_AT_HEAD

node scripts/release-check.mjs --ci

PKG_VERSION="$(node -p "require('./apps/local-agent/package.json').version")"
if npm view "@agentreel/agent@${PKG_VERSION}" version >/dev/null 2>&1; then
  echo "@agentreel/agent@${PKG_VERSION} is already on npm" >&2
  exit 1
fi
echo "ok: @agentreel/agent@${PKG_VERSION} is not on npm yet"
