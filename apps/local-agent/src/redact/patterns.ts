// Order matters. Multiline / specific patterns first, generic last.

export interface RedactionRule {
  name: string;
  re: RegExp;
  replacement: string | ((match: string) => string);
}

export const PATTERNS: RedactionRule[] = [
  // PEM-encoded private keys (multiline, must run early)
  {
    name: "pem-private-key",
    re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replacement: "[REDACTED:private-key]",
  },

  // JWT (header.payload.signature) — eyJ-prefixed base64url segments
  {
    name: "jwt",
    re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    replacement: "[REDACTED:jwt]",
  },

  // GitHub fine-grained PATs (84 chars after prefix is the official format)
  {
    name: "github-fine-grained-pat",
    re: /\bgithub_pat_[A-Za-z0-9_]{82,}\b/g,
    replacement: "[REDACTED:gh-fine-pat]",
  },
  // GitHub OAuth, PAT, app, server, refresh tokens
  {
    name: "github-token",
    re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    replacement: "[REDACTED:gh-token]",
  },

  // Anthropic
  {
    name: "anthropic-key",
    re: /\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{40,}\b/g,
    replacement: "[REDACTED:anthropic-key]",
  },

  // OpenAI (sk-proj-..., sk-svcacct-..., legacy sk-...)
  {
    name: "openai-key",
    re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b/g,
    replacement: "[REDACTED:openai-key]",
  },

  // Stripe
  {
    name: "stripe-secret",
    re: /\bsk_(?:test|live)_[A-Za-z0-9]{16,}\b/g,
    replacement: "[REDACTED:stripe-secret]",
  },
  {
    name: "stripe-restricted",
    re: /\brk_(?:test|live)_[A-Za-z0-9]{16,}\b/g,
    replacement: "[REDACTED:stripe-restricted]",
  },
  {
    name: "stripe-publishable",
    re: /\bpk_(?:test|live)_[A-Za-z0-9]{16,}\b/g,
    replacement: "[REDACTED:stripe-publishable]",
  },
  {
    name: "stripe-webhook",
    re: /\bwhsec_[A-Za-z0-9]{32,}\b/g,
    replacement: "[REDACTED:stripe-webhook]",
  },

  // AWS access key IDs (and STS / temporary forms)
  {
    name: "aws-access-key-id",
    re: /\b(?:AKIA|ASIA|AGPA|AROA|AIDA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b/g,
    replacement: "[REDACTED:aws-key-id]",
  },

  // Slack tokens
  {
    name: "slack-token",
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    replacement: "[REDACTED:slack-token]",
  },

  // Google API keys
  {
    name: "google-api-key",
    re: /\bAIza[A-Za-z0-9_-]{35}\b/g,
    replacement: "[REDACTED:google-api-key]",
  },

  // npm tokens
  {
    name: "npm-token",
    re: /\bnpm_[A-Za-z0-9]{36}\b/g,
    replacement: "[REDACTED:npm-token]",
  },

  // dotenv-style KEY=VALUE on its own line, where the KEY name looks sensitive.
  // This is a fallback for arbitrary secrets that don't match a specific
  // provider pattern. Captures the key, replaces the value.
  {
    name: "dotenv-secret",
    re: /^(\s*(?:export\s+)?[A-Z][A-Z0-9_]*?(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|API|AUTH|CREDENTIAL|PRIVATE|SESSION|COOKIE|BEARER|DSN)[A-Z0-9_]*\s*=\s*)(['"]?)([^\n'"]{4,})\2/gm,
    replacement: (m: string) => {
      // m is the full match; we keep the "KEY=" and quote, replace the value.
      // Re-run a small regex against m to preserve the prefix.
      const inner =
        /^(\s*(?:export\s+)?[A-Z][A-Z0-9_]*\s*=\s*)(['"]?)([^\n'"]{4,})\2/.exec(m);
      if (!inner) return "[REDACTED:dotenv-secret]";
      const [, prefix, quote] = inner;
      return `${prefix ?? ""}${quote ?? ""}[REDACTED:dotenv-secret]${quote ?? ""}`;
    },
  },

  // Email addresses
  {
    name: "email",
    re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    replacement: "[REDACTED:email]",
  },

  // IPv4 — validates each octet is 0-255 to cut version-string false positives.
  // Skips three benign forms below in the post-filter.
  {
    name: "ipv4",
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
    replacement: (m: string) => {
      if (m === "0.0.0.0" || m === "127.0.0.1" || m === "255.255.255.255") return m;
      return "[REDACTED:ip]";
    },
  },
];

// Sensitive key-name shapes used by the recursive object walker. If an
// object's key name matches AND the value is a non-trivial string, we redact
// the whole value regardless of provider-pattern match.
// Names that almost-always carry a secret value. Avoid generic words like
// `session` (matches `session_id`) or bare `token` (matches `csrf_token`
// inputs that are themselves not sensitive in our context).
export const SENSITIVE_KEY_RE =
  /(?:^|[_\-.])(?:api[_-]?key|access[_-]?token|secret|password|passwd|pwd|authorization|bearer|credential|private[_-]?key|client[_-]?secret|webhook[_-]?secret|service[_-]?account|refresh[_-]?token)(?:$|[_\-.])/i;
