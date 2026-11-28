# Policy signing key

Enforcing org policies from `GET /api/v1/policy` are signed with Ed25519
(agentreel/web `docs/govern-api.md` section 7.2). The server reads the
private key from `POLICY_SIGNING_PRIVATE_KEY` (PKCS#8 PEM, from GCP Secret
Manager). The CLI trusts only the public keys pinned in
`apps/local-agent/src/policy/pinned-keys.ts`.

## Pinned keys

`PINNED_POLICY_KEYS` maps a key id to its public key:

```ts
export const PINNED_POLICY_KEYS: Readonly<Record<string, string>> = Object.freeze({
  "ed25519-0123456789abcdef": "<base64url raw 32-byte public key>",
});
```

- At most two keys: the current one and the next one during a rotation. A
  third entry fails config validation (`validatePinnedPolicyKeys`), and the
  CLI then trusts no key at all, so it fails closed.
- Each key id must be `ed25519-` plus the first 16 hex characters of
  SHA-256 over the raw public key, and must match its public key.
- A policy signed with a key id that is not pinned, or with no key id, is
  rejected. For an enforcing org policy that means enforced lockdown (the
  enforced-org marker), not "no policy".

## Generating the production key

Run this yourself, from a machine where `gcloud` is logged in to the
production project. CI and agents never run it.

```sh
node scripts/generate-policy-signing-key.mjs --project <gcp-project-id>
```

What it does:

1. Refuses to continue if the secret `POLICY_SIGNING_PRIVATE_KEY` already
   exists (pass `--add-version` only for a rotation, see below).
2. Generates an Ed25519 key pair in memory.
3. Sends the private key (PKCS#8 PEM) to
   `gcloud secrets create POLICY_SIGNING_PRIVATE_KEY --data-file=-` on stdin.
   With `--via-temp-file` it instead writes a 0600 file in a fresh 0700 temp
   directory, passes `--data-file=<file>`, then overwrites and deletes the file
   whatever gcloud returned. Use this only if stdin does not work for you.
4. Prints only two lines to stdout:

   ```
   key_id=ed25519-<16 hex>
   public_key=<base64url>
   ```

The private key is never printed, logged, or written anywhere else. gcloud's
own output goes to stderr. If gcloud fails, nothing is printed to stdout and
the generated key is discarded.

`GCLOUD_BIN` overrides the gcloud binary; the test
(`apps/local-agent/test/policy-signing-key-script.test.ts`) uses a mock and
checks that no private key material reaches stdout or stderr.

## Order of operations

1. Generate the key with the script (above). Keep the two stdout lines.
2. Open a CLI pull request that adds the key id and public key to
   `PINNED_POLICY_KEYS`, and release it.
3. Only then deploy the web server with `POLICY_SIGNING_PRIVATE_KEY` mapped
   (Cloud Build `--set-secrets`). Until step 2 ships, CLIs reject every
   enforcing policy signed with the new key.

## Rotation

1. `node scripts/generate-policy-signing-key.mjs --project <id> --add-version`
   (adds a new secret version; the server switches on its next deploy or
   restart that reads `:latest`). Do this only after step 2.
2. Before that, release a CLI that pins both the current and the new key.
3. After the switch, a later release drops the old key.

Revocation is a CLI release that removes the compromised key id.
