import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

/**
 * Agent side of the signed policy wire (agentreel/web govern-api.md section
 * 7.2, contract.ts "7.1 Signed policy"). GET /api/v1/policy returns the
 * Policy body plus `signature: { alg: "Ed25519", key_id, signed_at, value }`.
 *
 * Signed bytes: UTF-8 of "agentreel-policy-sig-v1\n" + RFC 8785 canonical JSON
 * of the raw body with `signature` replaced by `{ alg, key_id, signed_at }`.
 * Key id: "ed25519-" + first 16 hex of SHA-256 over the 32-byte raw public key.
 * Public keys are pinned in the CLI (pinned-keys.ts) and never fetched.
 */

export const POLICY_SIGNATURE_ALG = "Ed25519";
export const POLICY_SIGNATURE_CONTEXT = "agentreel-policy-sig-v1";
export const POLICY_KEY_ID_RE = /^ed25519-[0-9a-f]{16}$/;
export const POLICY_SIGNATURE_VALUE_RE = /^[A-Za-z0-9_-]{86}$/;
export const POLICY_KEY_ID_HEADER = "x-agentreel-policy-key-id";
const ISO_UTC_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const CANONICAL_MAX_DEPTH = 64;

export interface PinnedPolicyKey {
  /** ed25519-<16 hex>; must equal policyKeyId(publicKey). */
  keyId: string;
  /** Raw 32-byte Ed25519 public key, base64url without padding. */
  publicKey: string;
}

export interface PolicySignature {
  alg: "Ed25519";
  key_id: string;
  signed_at: string;
  value: string;
}

export type SignatureFailure =
  | "missing_signature"
  | "malformed_signature"
  | "unknown_key_id"
  | "key_id_mismatch"
  | "bad_signature"
  | "not_canonicalizable";

export type SignatureCheck =
  | { ok: true; keyId: string; signedAt: string }
  | { ok: false; reason: SignatureFailure; detail: string };

function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        i += 1;
        continue;
      }
      return true;
    }
    if (c >= 0xdc00 && c <= 0xdfff) return true;
  }
  return false;
}

function ownProp(obj: object, key: string | number): unknown {
  const d = Object.getOwnPropertyDescriptor(obj, key);
  return d && "value" in d ? d.value : undefined;
}

function canonicalizeValue(value: unknown, depth: number): string {
  if (depth > CANONICAL_MAX_DEPTH) throw new RangeError("canonical JSON: nesting too deep");
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new RangeError("canonical JSON: non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    if (hasLoneSurrogate(value)) throw new RangeError("canonical JSON: lone surrogate");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (let i = 0; i < value.length; i += 1) {
      if (!Object.hasOwn(value, i)) throw new RangeError("canonical JSON: sparse array");
      const item = ownProp(value, i);
      if (item === undefined) throw new RangeError("canonical JSON: undefined array item");
      parts.push(canonicalizeValue(item, depth + 1));
    }
    return `[${parts.join(",")}]`;
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError("canonical JSON: only plain objects");
    }
    // RFC 8785: member names sorted by UTF-16 code units (default JS sort).
    const keys = Object.keys(value).sort();
    const parts: string[] = [];
    for (const key of keys) {
      if (hasLoneSurrogate(key)) throw new RangeError("canonical JSON: lone surrogate in key");
      const item = ownProp(value, key);
      if (item === undefined) continue;
      parts.push(`${JSON.stringify(key)}:${canonicalizeValue(item, depth + 1)}`);
    }
    return `{${parts.join(",")}}`;
  }
  throw new TypeError(`canonical JSON: unsupported type ${typeof value}`);
}

/** RFC 8785 (JCS) canonical JSON, byte-identical to the web contract's canonicalPolicyJson. */
export function canonicalPolicyJson(value: unknown): string {
  return canonicalizeValue(value, 0);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** The exact string whose UTF-8 bytes the server signs. Throws without a signature object. */
export function policySigningInput(rawPolicy: unknown): string {
  if (!isPlainObject(rawPolicy)) throw new TypeError("policy must be an object");
  const sig = ownProp(rawPolicy, "signature");
  if (!isPlainObject(sig)) throw new TypeError("policy.signature must be an object");
  const payload: Record<string, unknown> = Object.create(null);
  for (const key of Object.keys(rawPolicy)) {
    if (key === "signature") continue;
    payload[key] = ownProp(rawPolicy, key);
  }
  payload.signature = {
    alg: ownProp(sig, "alg"),
    key_id: ownProp(sig, "key_id"),
    signed_at: ownProp(sig, "signed_at"),
  };
  return `${POLICY_SIGNATURE_CONTEXT}\n${canonicalPolicyJson(payload)}`;
}

/** ed25519-<first 16 hex of SHA-256(raw 32-byte public key)>. */
export function policyKeyId(rawPublicKey: Uint8Array): string {
  return `ed25519-${createHash("sha256").update(rawPublicKey).digest("hex").slice(0, 16)}`;
}

/** Parses and shape-checks `signature`, mirroring policySignatureSchema (strict). */
export function readPolicySignature(rawPolicy: unknown): PolicySignature | null {
  if (!isPlainObject(rawPolicy)) return null;
  const sig = ownProp(rawPolicy, "signature");
  if (!isPlainObject(sig)) return null;
  const keys = Object.keys(sig).sort().join(",");
  if (keys !== "alg,key_id,signed_at,value") return null;
  const { alg, key_id, signed_at, value } = sig;
  if (alg !== POLICY_SIGNATURE_ALG) return null;
  if (typeof key_id !== "string" || !POLICY_KEY_ID_RE.test(key_id)) return null;
  if (typeof signed_at !== "string" || !ISO_UTC_RE.test(signed_at) || Number.isNaN(Date.parse(signed_at))) {
    return null;
  }
  if (typeof value !== "string" || !POLICY_SIGNATURE_VALUE_RE.test(value)) return null;
  return { alg, key_id, signed_at, value };
}

export function hasSignatureField(rawPolicy: unknown): boolean {
  return isPlainObject(rawPolicy) && Object.hasOwn(rawPolicy, "signature");
}

/**
 * Verifies a raw signed policy body against the pinned keys (steps 1 to 4 of
 * the contract's agent verification). Never throws.
 */
export function verifyPolicySignature(
  rawPolicy: unknown,
  pinnedKeys: readonly PinnedPolicyKey[],
): SignatureCheck {
  try {
    if (!hasSignatureField(rawPolicy)) {
      return { ok: false, reason: "missing_signature", detail: "policy has no signature" };
    }
    const sig = readPolicySignature(rawPolicy);
    if (!sig) {
      return { ok: false, reason: "malformed_signature", detail: "signature does not match the contract shape" };
    }
    const pinned = pinnedKeys.find((k) => k.keyId === sig.key_id);
    if (!pinned) {
      return { ok: false, reason: "unknown_key_id", detail: `key_id ${sig.key_id} is not pinned in this CLI` };
    }
    const raw = Buffer.from(pinned.publicKey, "base64url");
    if (raw.length !== 32 || policyKeyId(raw) !== sig.key_id) {
      return { ok: false, reason: "key_id_mismatch", detail: `pinned key does not hash to ${sig.key_id}` };
    }
    let input: string;
    try {
      input = policySigningInput(rawPolicy);
    } catch (err) {
      return { ok: false, reason: "not_canonicalizable", detail: (err as Error).message };
    }
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pinned.publicKey }, format: "jwk" });
    const signature = Buffer.from(sig.value, "base64url");
    if (signature.length !== 64 || !cryptoVerify(null, Buffer.from(input, "utf8"), key, signature)) {
      return { ok: false, reason: "bad_signature", detail: "Ed25519 signature does not verify" };
    }
    return { ok: true, keyId: sig.key_id, signedAt: sig.signed_at };
  } catch (err) {
    return { ok: false, reason: "bad_signature", detail: (err as Error).message || "verification error" };
  }
}
