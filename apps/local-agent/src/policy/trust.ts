import { pinnedPolicyKeys, signedEnforcingPolicyRequired } from "./pinned-keys.js";
import {
  hasSignatureField,
  readPolicySignature,
  verifyPolicySignature,
  type SignatureFailure,
} from "./signature.js";
import { getPolicyOrgId, type Policy } from "./types.js";

export type PolicyTrust =
  | { ok: true; signed: boolean; keyId?: string; signedAt?: string }
  | { ok: false; reason: SignatureFailure; detail: string };

/** An org policy in enforce mode: the case the contract says must be signed. */
export function isEnforcingOrgPolicy(policy: Policy): boolean {
  return policy.mode === "enforce" && getPolicyOrgId(policy) !== null;
}

/**
 * Decides whether a policy may be used.
 * - A body that carries a signature must verify against a pinned key, in any mode.
 * - An enforcing org policy without a signature is rejected (fail closed).
 * - Observe and no-org policies without a signature are accepted: they never block.
 */
export function checkPolicyTrust(policy: Policy, rawBody: unknown): PolicyTrust {
  if (rawBody !== undefined && hasSignatureField(rawBody)) {
    const res = verifyPolicySignature(rawBody, pinnedPolicyKeys());
    if (!res.ok) return res;
    return { ok: true, signed: true, keyId: res.keyId, signedAt: res.signedAt };
  }
  if (signedEnforcingPolicyRequired() && isEnforcingOrgPolicy(policy)) {
    return {
      ok: false,
      reason: "missing_signature",
      detail: "enforcing org policy is not signed",
    };
  }
  return { ok: true, signed: false };
}

export function signedAtOf(rawBody: unknown): string | null {
  return readPolicySignature(rawBody)?.signed_at ?? null;
}
