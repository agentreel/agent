# Threat model: NODE_OPTIONS

The command-text NODE_OPTIONS check (self-protect SELF005) is a best-effort
guard, not a sandbox. It inspects the hook or CLI command string and denies
assignments that are not on the six-flag allow list
(`--max-old-space-size`, `--max-semi-space-size`, `--enable-source-maps`,
`--no-warnings`, `--trace-warnings`, `--dns-result-order`).

It cannot see names built at runtime, including:

- `eval` with hex escapes
- `printf ... | bash`
- `base64 ... | bash`
- string concatenation

Those paths are covered by the runtime self-check. At hook-runner startup and
CLI startup, AgentReel reads `process.env.NODE_OPTIONS` before loading
anything else. If the effective value contains any token outside the allow
list, the process fails closed with SELF005: the CLI exits non-zero, and a
hook denies the call. Unset or empty values, and allow-listed flags, pass.
Unparseable values fail closed.

The runtime check is the backstop on the value Node actually applied to this
process.
