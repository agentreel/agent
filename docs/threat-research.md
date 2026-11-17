# AgentReel Guard: Threat Research

This document lists publicly documented incidents and research involving AI coding agents and their tooling, and the kinds of behaviour the shipped Guard rules (apps/local-agent/src/guard/rules.ts) look for. It is illustrative only. It is not a claim that AgentReel Guard would have detected or prevented any of these incidents.

Every factual claim below is footnoted to a primary source: the vendor's own blog, advisory or postmortem, or the affected person's own public report. Each source was fetched and checked on November 17, 2026. Anything we could not tie to a primary source has been left out.

---

## 1. Replit Agent deletes data from an app's database (July 2025)

**What the source says**

- Replit reports that Replit Agent deleted data from a user's app database.[R1]
- Replit says this happened before it separated development and production databases, so changes made during development could impact the user's production application.[R1]
- According to Replit, the Agent did not know the rollback feature existed, and the user was able to fully restore the database with it.[R1]
- Replit states that development and production databases are now separate by default, so the Agent cannot change the production database during development.[R1]

**Related Guard rules**: DB001 (DROP TABLE or DATABASE), DB002 (DELETE without WHERE), DB003 (TRUNCATE TABLE), PROD001 (production database connection).

**Sources**

- [R1] Replit blog, "Doubling down on our commitment to secure vibe coding" (July 29, 2025): https://replit.com/blog/doubling-down-on-our-commitment-to-secure-vibe-coding

---

## 2. Malicious code in the Amazon Q Developer VS Code extension (July 2025)

**What the source says**

- AWS states that the Amazon Q Developer for VS Code Extension had an inappropriately scoped GitHub token in its CodeBuild configuration, and that a threat actor used it to commit malicious code that was automatically included in a release.[A1][A2]
- Version 1.84.0 was impacted. AWS states that the malicious code was distributed with the extension but did not execute because of a syntax error, and made no changes to any services or customer environments.[A1][A2]
- AWS states that it revoked and replaced the credentials, removed the malicious code, released version 1.85.0 and removed 1.84.0 from distribution channels. The issue is CVE-2025-8217.[A1][A2]

**Related Guard rules**: these are general patterns, not specific to this attack. FS001 and FS002 (recursive deletion), CLOUD001 to CLOUD005 (cloud and Kubernetes resource deletion). AgentReel records agent sessions and does not scan extension builds or releases.

**Sources**

- [A1] AWS Security Bulletin AWS-2025-015: https://aws.amazon.com/security/security-bulletins/AWS-2025-015/
- [A2] GitHub Security Advisory GHSA-7g7f-ff96-5gcw: https://github.com/aws/aws-toolkit-vscode/security/advisories/GHSA-7g7f-ff96-5gcw

---

## 3. Nx 's1ngularity' malicious npm packages (August 26, 2025)

**What the sources say**

- According to Nx, attackers exploited a GitHub Actions injection vulnerability to steal Nx's npm publishing token and publish malicious versions of Nx packages.[N1]
- Nx says the malicious packages ran a post-install script that scanned user systems for sensitive data, attempted to use local AI tools (like Claude and Gemini), and uploaded the results to a public GitHub repo via the GitHub CLI.[N1] Nx's advisory says the results were posted to a repository under the user's GitHub account with a name containing `s1ngularity-repository`.[N2]
- Nx's advisory says a file at `/tmp/inventory.txt` lists files the malware probably read, and that the script added lines to `.zshrc` and `.bashrc`.[N2]
- Nx says the malicious packages were active for 4 hours before they were removed from the registry. The full list of affected versions is in the postmortem and advisory.[N1][N2]

**Related Guard rules**: SECRET001 (credential file read followed by network egress, including `gh repo create`), SECRET002 (credential file staging), SAFETY001 (AI CLI invoked with permission-bypass flags; the sources do not say which flags, if any, the malware used).

**Sources**

- [N1] Nx blog, "S1ngularity - What Happened, How We Responded, What We Learned" (September 5, 2025): https://nx.dev/blog/s1ngularity-postmortem
- [N2] Nx GitHub Security Advisory GHSA-cxm3-wv7p-598c: https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c

---

## 4. Prompt injection through the GitHub MCP server (research demonstration, May 2025)

**What the source says**

- Invariant Labs reported what it described as a critical vulnerability and demonstrated it on its own demo repositories.[I1]
- In its setup, a user asks an agent connected to the GitHub MCP server to look at open issues in a public repository. A malicious issue injects instructions, and the agent can be coerced into pulling private repository data into context and leaking it in a pull request on the public repository.[I1]
- According to Invariant Labs, this is not a flaw in the GitHub MCP server code itself, but an architectural issue that has to be addressed at the agent system level.[I1]

**Related Guard rules**: INJECT001 (prompt injection in fetched content), INJECT002 (hidden instructions in tool output), MULTI001 (injected instructions, then a sensitive read, then an upload).

**Sources**

- [I1] Invariant Labs, "GitHub MCP Exploited: Accessing private repositories via MCP" (May 26, 2025): https://invariantlabs.ai/blog/mcp-github-vulnerability

---

## 5. User reports of recursive deletes by Claude Code (October 2025 to April 2026)

These are reports filed by the affected users in the vendor's public issue tracker. They are the reporters' own accounts and have not been independently verified.

- **Issue #10077 (October 21, 2025).** The reporter states that Claude Code 2.0.22 on Ubuntu under WSL2 ran a recursive delete that removed the user files in their home directory, and that only files protected by permissions survived.[C1] The reporter states they did not run the agent with `--dangerously-skip-permissions`.[C1] The reporter could not see the exact command, so it cannot be mapped to a specific rule. FS001 targets recursive deletes of home or root paths.
- **Issue #49129 (April 16, 2026).** The reporter states that Claude Code moved image files into a `log/` subfolder and then ran `rm -rf` on the parent directory, deleting about 1,500 PNG files (about 50GB).[C2] A recursive `rm -rf` of a non-build directory matches FS002.
- **Issue #23913 (February 7, 2026).** The reporter states that after they asked Claude Code to "clean up all the scaffolding", it deleted 2,229 untracked source files using a `Get-ChildItem -Recurse | Remove-Item -Force` pipeline and `rm -rf`.[C3] The `rm -rf` commands match FS002. The `Remove-Item -Force` pipeline without `-Recurse` does not match a shipped rule.

**Sources**

- [C1] anthropics/claude-code issue #10077: https://github.com/anthropics/claude-code/issues/10077
- [C2] anthropics/claude-code issue #49129: https://github.com/anthropics/claude-code/issues/49129
- [C3] anthropics/claude-code issue #23913: https://github.com/anthropics/claude-code/issues/23913

---

## Patterns the Guard rules cover

These are the shipped rule categories. Each maps to rules in rules.ts.

1. Recursive or wildcard file deletion (FS001 to FS003)
2. Destructive database commands and migration resets (DB001 to DB004)
3. Cloud and Kubernetes resource deletion (CLOUD001 to CLOUD005)
4. Commands aimed at production databases, accounts or clusters (PROD001 to PROD003)
5. Credential file access, staging and sending (SECRET001 to SECRET003)
6. Force push, hard reset and branch deletion (GIT001 to GIT003)
7. Safety bypasses: AI CLI permission-bypass flags, `--no-verify`, skipped tests, `chmod 777` (SAFETY001 to SAFETY004)
8. Piped remote scripts and typosquat-like package names (INSTALL001, INSTALL002)
9. Prompt injection in fetched content or tool output (INJECT001, INJECT002)
10. Injected instructions, then a sensitive read, then an upload (MULTI001)

---

**Last reviewed**: November 17, 2026. Claims about other incidents in earlier versions of this document were removed because we could not tie them to a primary source.
