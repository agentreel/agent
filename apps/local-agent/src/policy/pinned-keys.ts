import type { PinnedPolicyKey } from "./signature.js";

/**
 * Ed25519 public keys this CLI release trusts for signed org policies
 * (agentreel/web govern-api.md section 7.2). They ship with the CLI and are
 * never fetched from the server.
 *
 * Rotation: a release pins the old and the new key, the server switches
 * POLICY_SIGNING_PRIVATE_KEY, then a later release drops the old key.
 * Revocation: a release that removes the compromised key id.
 *
 * Empty until the production signing key exists: the server PR does not
 * create POLICY_SIGNING_PRIVATE_KEY yet. Until a key is pinned here, no
 * enforcing org policy verifies, so the agent keeps its last verified cache
 * (or none). Never pin the test vector key (seed 0x01..0x20) here.
 */
export const PINNED_POLICY_KEYS: readonly PinnedPolicyKey[] = Object.freeze([]);

// Test overrides live on globalThis so they survive vi.resetModules(). Only
// in-process code can reach them; there is no env var or config for either.
const KEYS_SLOT = Symbol.for("agentreel.policy.pinnedKeysOverride");
const REQUIRED_SLOT = Symbol.for("agentreel.policy.signedEnforcingRequired");
type Slots = { [KEYS_SLOT]?: readonly PinnedPolicyKey[] | null; [REQUIRED_SLOT]?: boolean };
const slots = globalThis as unknown as Slots;

export function pinnedPolicyKeys(): readonly PinnedPolicyKey[] {
  return slots[KEYS_SLOT] ?? PINNED_POLICY_KEYS;
}

/**
 * True when an enforcing org policy must carry a valid signature. Only tests
 * turn this off (test/setup-policy-signing.ts), so suites written before
 * signing keep their unsigned fixtures. There is no env var or config for it.
 */
export function signedEnforcingPolicyRequired(): boolean {
  return slots[REQUIRED_SLOT] !== false;
}

/** Test hook: replace the pinned key set (null restores the shipped set). */
export function _setPinnedPolicyKeysForTests(keys: readonly PinnedPolicyKey[] | null): void {
  slots[KEYS_SLOT] = keys;
}

/** Test hook: see signedEnforcingPolicyRequired(). */
export function _setSignedPolicyRequiredForTests(required: boolean): void {
  slots[REQUIRED_SLOT] = required;
}
