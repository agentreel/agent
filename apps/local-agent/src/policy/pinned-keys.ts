import { POLICY_KEY_ID_RE, policyKeyId, type PinnedPolicyKey } from "./signature.js";

/** At most two keys: the current one and the next one during a rotation. */
export const MAX_PINNED_POLICY_KEYS = 2;

/**
 * Ed25519 public keys this CLI release trusts for signed org policies
 * (agentreel/web govern-api.md section 7.2), keyed by key id
 * (`ed25519-<first 16 hex of SHA-256(raw public key)>`). The value is the raw
 * 32-byte public key, base64url without padding. They ship with the CLI and
 * are never fetched from the server.
 *
 * At most two keys (current and next). A signature whose key id is not
 * listed here is rejected, and an enforcing org policy then fails closed
 * (enforced lockdown through the enforced-org marker).
 *
 * Rotation: a release pins the current and the next key, the server switches
 * POLICY_SIGNING_PRIVATE_KEY, then a later release drops the old key.
 * Revocation: a release that removes the compromised key id.
 *
 * This release pins the production key stored as POLICY_SIGNING_PRIVATE_KEY
 * version 1 (key id ed25519-1091560a744b8a9e). There is no next key yet.
 * Generate a rotation key with scripts/generate-policy-signing-key.mjs
 * (docs/policy-signing-key.md). Never pin the test vector key (seed 0x01..0x20).
 */
export const PINNED_POLICY_KEYS: Readonly<Record<string, string>> = Object.freeze({
  "ed25519-1091560a744b8a9e": "p9YDgiP5XFmVGoNtZDc4Ea70zAmt_fIDptdAlaF-cXo",
});

/**
 * Checks a pinned key map and returns it as a list. Throws on more than
 * MAX_PINNED_POLICY_KEYS entries, a key id that is not `ed25519-<16 hex>`, a
 * public key that is not 32 raw bytes, or a key id that does not match its
 * public key.
 */
export function validatePinnedPolicyKeys(map: Readonly<Record<string, string>>): PinnedPolicyKey[] {
  const entries = Object.entries(map);
  if (entries.length > MAX_PINNED_POLICY_KEYS) {
    throw new Error(
      `PINNED_POLICY_KEYS holds ${entries.length} keys; at most ${MAX_PINNED_POLICY_KEYS} (current and next) are allowed`,
    );
  }
  return entries.map(([keyId, publicKey]) => {
    if (!POLICY_KEY_ID_RE.test(keyId)) throw new Error(`pinned key id ${keyId} is not ed25519-<16 hex>`);
    if (typeof publicKey !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(publicKey)) {
      throw new Error(`pinned key ${keyId} is not a base64url 32-byte public key`);
    }
    const raw = Buffer.from(publicKey, "base64url");
    if (raw.length !== 32 || policyKeyId(raw) !== keyId) {
      throw new Error(`pinned key ${keyId} does not hash to its key id`);
    }
    return { keyId, publicKey };
  });
}

// Test overrides live on globalThis so they survive vi.resetModules(). Only
// in-process code can reach them; there is no env var or config for either.
const KEYS_SLOT = Symbol.for("agentreel.policy.pinnedKeysOverride");
const REQUIRED_SLOT = Symbol.for("agentreel.policy.signedEnforcingRequired");
type Slots = { [KEYS_SLOT]?: Readonly<Record<string, string>> | null; [REQUIRED_SLOT]?: boolean };
const slots = globalThis as unknown as Slots;

/**
 * The pinned keys, validated. An invalid set (for example a third key)
 * yields no keys at all, so every signed policy is rejected and an enforcing
 * org policy fails closed.
 */
export function pinnedPolicyKeys(): readonly PinnedPolicyKey[] {
  try {
    return validatePinnedPolicyKeys(slots[KEYS_SLOT] ?? PINNED_POLICY_KEYS);
  } catch {
    return [];
  }
}

/**
 * True when an enforcing org policy must carry a valid signature. Only tests
 * turn this off (test/setup-policy-signing.ts), so suites written before
 * signing keep their unsigned fixtures. There is no env var or config for it.
 */
export function signedEnforcingPolicyRequired(): boolean {
  return slots[REQUIRED_SLOT] !== false;
}

/**
 * Test hook: replace the pinned key set (null restores the shipped set). A
 * list is converted to the kid-keyed map; either form goes through the same
 * validation as the shipped set.
 */
export function _setPinnedPolicyKeysForTests(
  keys: Readonly<Record<string, string>> | readonly PinnedPolicyKey[] | null,
): void {
  if (keys === null || !Array.isArray(keys)) {
    slots[KEYS_SLOT] = keys as Readonly<Record<string, string>> | null;
    return;
  }
  const map: Record<string, string> = {};
  for (const k of keys as readonly PinnedPolicyKey[]) map[k.keyId] = k.publicKey;
  slots[KEYS_SLOT] = map;
}

/** Test hook: see signedEnforcingPolicyRequired(). */
export function _setSignedPolicyRequiredForTests(required: boolean): void {
  slots[REQUIRED_SLOT] = required;
}
