import { describe, expect, it } from "vitest";
import { scrubAny, scrubString } from "../src/redact/scrubber.js";

// Build fake secrets at runtime so this file never contains a string that
// looks like a real credential to secret scanners.
const rep = (c: string, n: number) => c.repeat(n);

describe("connection strings", () => {
  const cases: Array<[string, string]> = [
    ["postgres://m:Sup3r@db.internal:5432/app", "postgres://m:[REDACTED:password]@db.internal:5432/app"],
    ["postgresql://admin:p%40ss@10.0.0.5/db", "postgresql://admin:[REDACTED:password]@[REDACTED:ip]/db"],
    ["mysql://root:hunter2@localhost:3306/shop", "mysql://root:[REDACTED:password]@localhost:3306/shop"],
    [
      "mongodb+srv://svc:Zx9qL2@cluster0.ab1cd.mongodb.net/prod?retryWrites=true",
      "mongodb+srv://svc:[REDACTED:password]@cluster0.ab1cd.mongodb.net/prod?retryWrites=true",
    ],
    ["redis://:s3cretpw@cache:6379/0", "redis://:[REDACTED:password]@cache:6379/0"],
    ["amqp://guest:guestpw@rabbit:5672/", "amqp://guest:[REDACTED:password]@rabbit:5672/"],
    ["https://bot:tok123456@github.com/org/repo.git", "https://bot:[REDACTED:password]@github.com/org/repo.git"],
  ];
  for (const [input, expected] of cases) {
    it(input.split(":")[0]!, () => expect(scrubString(input)).toBe(expected));
  }

  it("catches the db_url case from the field test", () => {
    const out = scrubString("db_url=postgres://m:Sup3r@prod-db:5432/core");
    expect(out).not.toContain("Sup3r");
    expect(out).toContain("prod-db");
  });

  it("leaves URLs without credentials alone", () => {
    expect(scrubString("see https://example.com:8080/path")).toBe("see https://example.com:8080/path");
  });
});

describe("authorization", () => {
  it("redacts Bearer tokens in headers and curl", () => {
    const tok = "abc." + rep("x", 30);
    const out = scrubString(`curl -H "Authorization: Bearer ${tok}" https://api.example.com`);
    expect(out).toBe('curl -H "Authorization: Bearer [REDACTED:auth-token]" https://api.example.com');
  });
  it("redacts Basic auth", () => {
    expect(scrubString("Authorization: Basic dXNlcjpwYXNzd29yZA==")).toBe(
      "Authorization: Basic [REDACTED:auth-token]",
    );
  });
  it("redacts bare API key headers", () => {
    expect(scrubString("X-Api-Key: " + rep("k", 24))).toBe("X-Api-Key: [REDACTED:auth-header]");
  });
  it("redacts the Authorization value in JSON", () => {
    const out = scrubString(JSON.stringify({ headers: { Authorization: "Bearer " + rep("z", 20) } }));
    expect(out).not.toContain(rep("z", 20));
  });
  it("does not eat normal prose", () => {
    expect(scrubString("The Bearer of bad news")).toBe("The Bearer of bad news");
  });
});

describe("provider tokens", () => {
  it("AWS access key id and secret", () => {
    const id = "AKIA" + rep("A", 16);
    const secret = rep("a", 20) + rep("B", 16) + "/+=0";
    const out = scrubString(`aws_access_key_id = ${id}\naws_secret_access_key = ${secret}`);
    expect(out).toBe("aws_access_key_id = [REDACTED:aws-key-id]\naws_secret_access_key = [REDACTED:aws-secret]");
  });
  it("GitHub classic and fine-grained tokens", () => {
    expect(scrubString("ghp_" + rep("a", 36))).toBe("[REDACTED:gh-token]");
    expect(scrubString("github_pat_" + rep("A", 82))).toBe("[REDACTED:gh-fine-pat]");
  });
  it("Slack tokens and webhooks", () => {
    expect(scrubString("xoxb-" + rep("1", 12) + "-" + rep("a", 24))).toBe("[REDACTED:slack-token]");
    expect(scrubString("xapp-1-" + rep("A", 30))).toBe("[REDACTED:slack-token]");
    expect(scrubString("https://hooks.slack.com/services/T000/B000/" + rep("x", 24))).toBe(
      "https://hooks.slack.com/[REDACTED:slack-webhook]",
    );
  });
  it("OpenAI and Anthropic keys", () => {
    expect(scrubString("sk-proj-" + rep("a", 40))).toBe("[REDACTED:openai-key]");
    expect(scrubString("sk-ant-api03-" + rep("b", 90))).toBe("[REDACTED:anthropic-key]");
  });
  it("JWTs", () => {
    const jwt = "eyJ" + rep("a", 20) + ".eyJ" + rep("b", 20) + "." + rep("c", 20);
    expect(scrubString(`token=${jwt}`)).not.toContain(rep("b", 20));
  });
  it("private key blocks, including PGP", () => {
    const pem = `-----BEGIN RSA PRIVATE KEY-----\n${rep("M", 64)}\n-----END RSA PRIVATE KEY-----`;
    expect(scrubString(pem)).toBe("[REDACTED:private-key]");
    const pgp = `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${rep("Q", 64)}\n-----END PGP PRIVATE KEY BLOCK-----`;
    expect(scrubString(pgp)).toBe("[REDACTED:private-key]");
  });
});

describe("password assignments", () => {
  it("query strings and config", () => {
    expect(scrubString("login?user=a&password=hunter22&x=1")).toBe("login?user=a&password=[REDACTED:password]&x=1");
    expect(scrubString('{"password": "hunter22"}')).toBe('{"password": "[REDACTED:password]"}');
    expect(scrubString("mysql -u root --password=hunter22")).toBe("mysql -u root --password=[REDACTED:password]");
  });
  it("leaves type annotations alone", () => {
    expect(scrubString("  password: string;")).toBe("  password: string;");
  });
  it("uppercase dotenv lines", () => {
    expect(scrubString("DB_PASSWORD=hunter22")).toBe("DB_PASSWORD=[REDACTED:dotenv-secret]");
  });
});

describe("scrubAny", () => {
  it("redacts by key name and walks nested values", () => {
    const out = scrubAny({
      tool_input: { command: "psql postgres://u:pw1234@h/db", apiKey: "plainvalue" },
      list: ["Bearer " + rep("t", 20)],
    });
    expect(out.tool_input.command).toBe("psql postgres://u:[REDACTED:password]@h/db");
    expect(out.tool_input.apiKey).toBe("[REDACTED:by-key-name]");
    expect(out.list[0]).toBe("Bearer [REDACTED:auth-token]");
  });
});

describe("idempotency", () => {
  it("running twice gives the same output", () => {
    const input = [
      "postgres://m:Sup3r@db/app",
      "Authorization: Bearer " + rep("q", 30),
      "password=hunter22",
      "X-Api-Key: " + rep("k", 24),
      "AKIA" + rep("Z", 16),
    ].join("\n");
    const once = scrubString(input);
    expect(scrubString(once)).toBe(once);
  });
});
