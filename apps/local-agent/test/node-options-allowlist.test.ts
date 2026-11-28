import { describe, expect, it } from "vitest";
import { hasDisallowedNodeOptions, isAllowedNodeOptionsValue, NODE_OPTIONS_ALLOWED_FLAGS } from "../src/policy/node-options.js";
import { matchSelfProtect } from "../src/policy/self-protect.js";

const rule = (command: string) => matchSelfProtect({ toolName: "Bash", command })?.rule_id ?? null;
const CLI = "/usr/local/lib/node_modules/@agentreel/agent/dist/cli.js";

describe("NODE_OPTIONS allow list (SELF005)", () => {
  it("lists exactly the six allowed flags", () => {
    expect([...NODE_OPTIONS_ALLOWED_FLAGS].sort()).toEqual([
      "--dns-result-order",
      "--enable-source-maps",
      "--max-old-space-size",
      "--max-semi-space-size",
      "--no-warnings",
      "--trace-warnings",
    ]);
  });

  const allowed = [
    "NODE_OPTIONS=--max-old-space-size=4096 node x",
    "NODE_OPTIONS='--max-old-space-size=4096 --no-warnings' node x",
    'NODE_OPTIONS="--max-old-space-size 4096 --enable-source-maps" node x',
    'NODE_OPTIONS="--dns-result-order=ipv4first --trace-warnings" npm test',
    "NODE_OPTIONS=--max-semi-space-size=64 pnpm test",
    "NODE_OPTIONS=--max_old_space_size=2048 node x",
    "env NODE_OPTIONS=--no-warnings node x",
    "sudo NODE_OPTIONS=--max-old-space-size=4096 node x",
    "sudo -E env NODE_OPTIONS=--enable-source-maps node x",
    'export NODE_OPTIONS="--max-old-space-size=8192"',
    "export NODE_OPTIONS=--max-old-space-size=4096",
    "NODE_OPTIONS= node x",
    "unset NODE_OPTIONS",
    "env -u NODE_OPTIONS node x",
    "echo $NODE_OPTIONS",
    `NODE_OPTIONS=--max-old-space-size=4096 node ${CLI} doctor`,
    "agentreel doctor",
    `node ${CLI} doctor`,
  ];
  for (const cmd of allowed) {
    it(`allows: ${cmd}`, () => expect(rule(cmd)).toBeNull());
  }

  const bad = [
    "-r /tmp/evil.js",
    "--require=/tmp/evil.js",
    "--require /tmp/evil.js",
    "--import=/tmp/evil.mjs",
    "--import /tmp/evil.mjs",
    "--loader=/tmp/l.mjs",
    "--experimental-loader=/tmp/l.mjs",
    "--inspect",
    "--inspect=0.0.0.0:9229",
    "--inspect-brk",
    "--env-file=/tmp/.env",
    "--unknown-flag",
    "--max-old-space-size=4096 --require=/tmp/evil.js",
    "--no-warnings -r /tmp/evil.js",
    "--max-old-space-size",
    "--max-old-space-size=abc",
    "--no-warnings=1",
    "--dns-result-order=evil",
    "--",
    "--=x",
    "- --require=/tmp/evil.js",
  ];
  const wrap: Array<[string, (v: string) => string]> = [
    ["bare", (v) => `NODE_OPTIONS='${v}' agentreel doctor`],
    ["env", (v) => `env NODE_OPTIONS='${v}' agentreel doctor`],
    ["sudo", (v) => `sudo NODE_OPTIONS='${v}' npx @agentreel/agent doctor`],
    ["sudo -E env", (v) => `sudo -E env NODE_OPTIONS='${v}' node ${CLI} doctor`],
    ["export", (v) => `export NODE_OPTIONS='${v}'`],
  ];
  for (const v of bad) {
    for (const [label, f] of wrap) {
      it(`denies ${label}: ${v}`, () => expect(rule(f(v))).toBe("SELF005"));
    }
  }

  const tricks = [
    "NODE_OPTIONS=--require=/tmp/evil.js node x",
    "NODE_OPTIONS=$EVIL node x",
    'NODE_OPTIONS="$(cat /tmp/opts)" node x',
    "NODE_OPTIONS=`cat /tmp/opts` node x",
    "NODE_OPTIONS='--max-old-space-size=4096 node x",
    'NODE_OPTIONS="--require /tmp/a.js" node x',
    "NODE_OPTIONS+=' --require=/tmp/evil.js' node x",
    "export NODE_OPTIONS+=--require=/tmp/evil.js",
    'env "NODE_OPTIONS=--require /tmp/evil.js" node x',
    'sh -c "NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor"',
    "bash -c 'export NODE_OPTIONS=--import=/tmp/e.mjs; agentreel doctor'",
    'eval "NODE_OPTIONS=--require=/tmp/evil.js node x"',
    "read NODE_OPTIONS < /tmp/opts",
    "printf -v NODE_OPTIONS %s --require=/tmp/evil.js",
    "declare -x NODE_OPTIONS=--require=/tmp/evil.js",
    "export NODE_OPTIONS",
    "NODE_OPTIONS=--max-old-space-size=4096; export NODE_OPTIONS",
    'NODE_OPTIONS="--require=\\"/tmp/a b.js\\"" node x',
  ];
  for (const cmd of tricks) {
    it(`denies trick: ${cmd}`, () => expect(rule(cmd)).toBe("SELF005"));
  }

  it("value checker: allowed and mixed values", () => {
    expect(isAllowedNodeOptionsValue("--max-old-space-size=4096 --no-warnings")).toBe(true);
    expect(isAllowedNodeOptionsValue('--max-old-space-size "4096"')).toBe(true);
    expect(isAllowedNodeOptionsValue("")).toBe(true);
    expect(isAllowedNodeOptionsValue("--no-warnings --require=x")).toBe(false);
    expect(isAllowedNodeOptionsValue('--no-warnings "--require=x')).toBe(false);
  });

  it("fails closed past the nesting depth cap, even for an allowed value", () => {
    expect(hasDisallowedNodeOptions("NODE_OPTIONS=--no-warnings node x", 3)).toBe(false);
    expect(hasDisallowedNodeOptions("NODE_OPTIONS=--no-warnings node x", 4)).toBe(true);
    const deep = `sh -c "bash -c 'sh -c \\"bash -c NODE_OPTIONS=--no-warnings\\"'"`;
    expect(rule(deep)).toBeNull();
    let five = "NODE_OPTIONS=--no-warnings node x";
    for (let i = 0; i < 5; i++) five = `sh -c ${JSON.stringify(five)}`;
    expect(rule(five)).toBe("SELF005");
  });

  it("is linear on long inputs", () => {
    const long = "NODE_OPTIONS='" + "--no-warnings ".repeat(20000) + "' node x";
    const t0 = Date.now();
    expect(hasDisallowedNodeOptions(long)).toBe(false);
    expect(Date.now() - t0).toBeLessThan(1000);
  });
});

// Circuit round 5 probe cases (probe-35-r5), copied as committed tests.
// One change: `export NODE_OPTIONS=--max-old-space-size=4096` is allowed
// under the allow list (Gabbar's call), so it is in the allowed set above.
describe("NODE_OPTIONS round 5 cases", () => {
  const doctor = `node ${CLI} doctor`;
  const denied = [
    `NODE_OPTIONS=--require=/tmp/evil.js ${doctor}`,
    `NODE_OPTIONS=--import=/tmp/evil.mjs ${doctor}`,
    `NODE_OPTIONS='--require /tmp/evil.js' ${doctor}`,
    `env NODE_OPTIONS=--require=/tmp/evil.js ${doctor}`,
    `sudo NODE_OPTIONS=--require=/tmp/evil.js ${doctor}`,
    `sudo env NODE_OPTIONS=--require=/tmp/evil.js ${doctor}`,
    `sudo -E env NODE_OPTIONS=--require=/tmp/evil.js ${doctor}`,
    "sudo -E env NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor",
    "sudo -E env NODE_OPTIONS=--import=/tmp/evil.mjs npx @agentreel/agent doctor",
    "export NODE_OPTIONS=--require=/tmp/evil.js",
    "NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor",
    "NODE_OPTIONS=--import=/tmp/evil.mjs agentreel doctor",
    "env NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor",
    "sudo NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js npx @agentreel/agent doctor",
    "env NODE_OPTIONS=--require=/tmp/evil.js npx @agentreel/agent doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js npm exec @agentreel/agent doctor",
    "NODE_OPTIONS=--import=/tmp/evil.mjs npm exec @agentreel/agent doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js npm run doctor",
    "NODE_OPTIONS=--import=/tmp/evil.mjs npm run build",
    "env NODE_OPTIONS=--require=/tmp/evil.js npm run test",
    "NODE_OPTIONS=--require=/tmp/evil.js pnpm exec @agentreel/agent doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js pnpm dlx @agentreel/agent doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js yarn exec @agentreel/agent doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js yarn run build",
    "FOO=1 NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor",
    "FOO=1 NODE_OPTIONS=--import=/tmp/evil.mjs node /usr/bin/node",
    "BAR=x NODE_OPTIONS='--require /tmp/evil.js' npm exec @agentreel/agent doctor",
    // Compound: assignment in its own segment, program in a later one.
    "NODE_OPTIONS=--require=/tmp/evil.js; agentreel doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js && agentreel doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js || agentreel doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js & agentreel doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js | agentreel doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js\nagentreel doctor",
    "NODE_OPTIONS=--require=/tmp/evil.js; npx @agentreel/agent doctor",
    `NODE_OPTIONS=--require=/tmp/evil.js && ${doctor}`,
    "export NODE_OPTIONS=--require=/tmp/evil.js; agentreel doctor",
    "true; export NODE_OPTIONS=--require=/tmp/evil.js",
    "cd /tmp && NODE_OPTIONS=--import=/tmp/e.mjs",
    // Lone assignment, no program.
    "NODE_OPTIONS=--require=x",
    "NODE_OPTIONS='--require x'",
    // Shell -c inner strings.
    'sh -c "NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor"',
    "bash -c 'NODE_OPTIONS=--require=/tmp/evil.js agentreel doctor'",
    "bash -lc 'export NODE_OPTIONS=--require=/tmp/evil.js; agentreel doctor'",
    'zsh -c "NODE_OPTIONS=--import=/tmp/e.mjs node x"',
    "dash -c 'NODE_OPTIONS=--inspect node x'",
    `sh -c "bash -c 'sh -c \\"NODE_OPTIONS=--require=x node y\\"'"`,
    "sh -c 'NODE_OPTIONS=\"$(cat /tmp/o)\" node x'",
    "sh -c 'NODE_OPTIONS=--no-warnings",
  ];
  for (const cmd of denied) {
    it(`denies ${JSON.stringify(cmd)}`, () => expect(rule(cmd)).toBe("SELF005"));
  }

  const allowed = [
    "agentreel doctor",
    "agentreel status",
    "agentreel init",
    doctor,
    "npx @agentreel/agent doctor",
    "npx @agentreel/agent status",
    "npm exec @agentreel/agent doctor",
    "npm run build",
    "npm test",
    "pnpm test",
    "yarn test",
    "HOME=/tmp/x npm test",
    "FOO=1 agentreel doctor",
    "FOO=1 BAR=2 npm test",
    "echo hello > out.txt",
    "echo NODE_OPTIONS=--require=/tmp/evil.js",
    "git status",
    "npm install left-pad",
    "cat ~/.claude/settings.json",
    "NODE_OPTIONS=--max-old-space-size=4096; agentreel doctor",
    "NODE_OPTIONS=--max-old-space-size=4096",
    "true && export NODE_OPTIONS='--no-warnings --enable-source-maps'",
    "bash -c 'NODE_OPTIONS=--max-old-space-size=4096 npm test'",
    'sh -c "NODE_OPTIONS=--no-warnings node x"',
  ];
  for (const cmd of allowed) {
    it(`allows ${JSON.stringify(cmd)}`, () => expect(rule(cmd)).toBeNull());
  }
});

describe("TEXT_ONLY piped into a bare shell, here-strings and heredocs", () => {
  const requireEq = "--require=/tmp/evil.js";
  const requireSp = "--require /tmp/evil.js";
  const importEq = "--import=/tmp/evil.mjs";
  const importSp = "--import /tmp/evil.mjs";
  const allowed = "--max-old-space-size=4096";

  const deniedPipes = [
    `printf 'NODE_OPTIONS=${requireEq} agentreel doctor' | sh`,
    `printf 'NODE_OPTIONS=${requireSp} agentreel doctor' | sh`,
    `printf 'NODE_OPTIONS=${importEq} agentreel doctor' | bash`,
    `printf 'NODE_OPTIONS=${importSp} agentreel doctor' | bash`,
    `echo 'NODE_OPTIONS=${requireEq} agentreel doctor' | bash`,
    `echo 'NODE_OPTIONS=${requireSp} agentreel doctor' | bash`,
    `echo 'NODE_OPTIONS=${importEq} agentreel doctor' | sh`,
    `echo 'NODE_OPTIONS=${importSp} agentreel doctor' | sh`,
    `printf 'NODE_OPTIONS=${requireEq} agentreel doctor' | /bin/sh`,
    // printf escapes and %s: expand or fail closed, either way deny the preload.
    `printf 'NODE_OPTIONS=${requireEq}\nagentreel doctor' | sh`,
    `printf 'NODE_OPTIONS=%s agentreel doctor' ${requireEq} | sh`,
  ];
  for (const cmd of deniedPipes) {
    it(`denies pipe: ${JSON.stringify(cmd)}`, () => expect(rule(cmd)).toBe("SELF005"));
  }

  it("allows a harmless echo | sh of an allowed value", () => {
    expect(rule(`echo 'NODE_OPTIONS=${allowed} agentreel doctor' | sh`)).toBeNull();
  });
  it("allows a harmless printf | bash of an allowed value", () => {
    expect(rule(`printf 'NODE_OPTIONS=${allowed} agentreel doctor' | bash`)).toBeNull();
  });
  it("echo of a bad value without a pipe is still just text", () => {
    expect(rule(`echo 'NODE_OPTIONS=${requireEq} agentreel doctor'`)).toBeNull();
  });

  const deniedHere = [
    `bash <<< 'NODE_OPTIONS=${requireEq} agentreel doctor'`,
    `sh <<< 'NODE_OPTIONS=${requireSp} agentreel doctor'`,
    `zsh <<< 'NODE_OPTIONS=${importEq} agentreel doctor'`,
    `dash <<< "NODE_OPTIONS=${importSp} agentreel doctor"`,
    `sh <<'EOF'\nNODE_OPTIONS=${requireEq} agentreel doctor\nEOF`,
    `bash <<EOF\nNODE_OPTIONS=${importEq} agentreel doctor\nEOF`,
    `sh <<'EOF'\nNODE_OPTIONS=${requireSp} agentreel doctor\nEOF`,
    `bash <<'END'\nNODE_OPTIONS=${importSp} agentreel doctor\nEND`,
  ];
  for (const cmd of deniedHere) {
    it(`denies here input: ${JSON.stringify(cmd)}`, () => expect(rule(cmd)).toBe("SELF005"));
  }

  it("allows a here-string with an allowed value", () => {
    expect(rule(`bash <<< 'NODE_OPTIONS=${allowed} agentreel doctor'`)).toBeNull();
  });
  it("allows an inline heredoc with an allowed value", () => {
    expect(rule(`sh <<'EOF'\nNODE_OPTIONS=${allowed} agentreel doctor\nEOF`)).toBeNull();
  });
  it("cat of a heredoc (not piped to a shell) is not executed, so it stays allowed", () => {
    expect(rule(`cat <<'EOF'\nNODE_OPTIONS=${requireEq}\nEOF`)).toBeNull();
  });
  it("cat file | sh is out of scope when the command text has no assignment", () => {
    expect(rule("cat /tmp/evil.sh | sh")).toBeNull();
  });
  it("source file is out of scope", () => {
    expect(rule("source /tmp/evil.sh")).toBeNull();
  });
});
