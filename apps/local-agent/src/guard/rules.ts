import type { Rule } from "./types.js";

export const RULES: Rule[] = [
  {
    id: "FS001",
    version: 1,
    severity: "critical",
    category: "filesystem-destruction",
    name: "Recursive home directory deletion",
    description: "Detects rm -rf or equivalent targeting home directory or root filesystem",
    rationale:
      "Irreversible deletion of entire home directory or filesystem. Documented in multiple incidents including Claude Code Mac wipe (Dec 2025) and WSL2 incident (Oct 2025).",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const cmdLower = cmd.toLowerCase();
        const hasRecursiveDelete =
          /\brm\s+[^|&;]*-[^|&;]*r[^|&;]*f\b/.test(cmdLower) ||
          /\brm\s+[^|&;]*-[^|&;]*f[^|&;]*r\b/.test(cmdLower) ||
          /\brmdir\s+\/s\s+\/q\b/i.test(cmd) ||
          /Remove-Item\s+[^|&;]*-Force[^|&;]*-Recurse/i.test(cmd) ||
          /Remove-Item\s+[^|&;]*-Recurse[^|&;]*-Force/i.test(cmd);

        if (!hasRecursiveDelete) return false;

        const dangerousPaths =
          /(\~\/|\/home\/[^\/\s]+\/?|\/Users\/[^\/\s]+\/?|\$HOME|\/\s|[A-Z]:\\\s|[A-Z]:\\$)/;
        return dangerousPaths.test(cmd);
      },
    },
  },

  {
    id: "FS002",
    version: 1,
    severity: "high",
    category: "filesystem-destruction",
    name: "Recursive directory deletion",
    description: "Detects recursive deletion of directories",
    rationale:
      "Can cause permanent data loss. Seen in Claude Code 50GB image deletion (Apr 2026) and 2,229 file deletion incidents.",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const hasRmRf =
          /\brm\s+-[a-z]*rf[a-z]*\b/i.test(cmd) ||
          /\brm\s+-[a-z]*fr[a-z]*\b/i.test(cmd);
        
        const hasRmdirForce = /\brmdir\s+\/s/i.test(cmd);
        
        const hasRemoveItemForce =
          /Remove-Item\s+[^|&;\n]*-Recurse[^|&;\n]*-Force/i.test(cmd) ||
          /Remove-Item\s+[^|&;\n]*-Force[^|&;\n]*-Recurse/i.test(cmd);

        const isDestructive = hasRmRf || hasRmdirForce || hasRemoveItemForce;
        if (!isDestructive) return false;
        
        const safePaths =
          /\b(node_modules|\.next|dist|build|target|out|\.cache|coverage|\.nuxt|\.output|vendor)\b/i;
        return !safePaths.test(cmd);
      },
    },
  },

  {
    id: "FS003",
    version: 1,
    severity: "warn",
    category: "filesystem-destruction",
    name: "Wildcard deletion in sensitive directory",
    description: "Detects deletion with wildcards in potentially sensitive locations",
    rationale: "Wildcards can expand unexpectedly and delete more than intended",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const hasWildcard = /\*/.test(cmd);
        const hasDelete =
          /\brm\b/.test(cmd) ||
          /\bdel\b/i.test(cmd) ||
          /Remove-Item/.test(cmd);
        const inSensitiveDir =
          /\/home\//.test(cmd) ||
          /\/Users\//.test(cmd) ||
          /\/root\//.test(cmd) ||
          /Documents/.test(cmd) ||
          /Desktop/.test(cmd);
        return hasWildcard && hasDelete && inSensitiveDir;
      },
    },
  },

  {
    id: "DB001",
    version: 1,
    severity: "critical",
    category: "database-destruction",
    name: "DROP TABLE or DATABASE",
    description: "Detects SQL DROP TABLE or DROP DATABASE commands",
    rationale:
      "Permanent data loss. Replit agent deleted 1,206 executive records (Jul 2025). Claude Code wiped Supabase database (Jul 2026).",
    enabled: true,
    matcher: {
      type: "db-operation",
      customMatcher: (ctx) => {
        const cmd = ctx.command?.toUpperCase() || "";
        const payload = JSON.stringify(ctx.payload || {}).toUpperCase();
        const text = cmd + " " + payload;
        return /\bDROP\s+(TABLE|DATABASE|SCHEMA)\b/.test(text);
      },
    },
  },

  {
    id: "DB002",
    version: 1,
    severity: "critical",
    category: "database-destruction",
    name: "DELETE without WHERE",
    description: "Detects DELETE statements without WHERE clause",
    rationale:
      "Deletes all rows from a table. Common pattern in production database incidents.",
    enabled: true,
    matcher: {
      type: "db-operation",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const payload = JSON.stringify(ctx.payload || {});
        const text = cmd + " " + payload;
        const hasDelete = /\bDELETE\s+FROM\b/i.test(text);
        if (!hasDelete) return false;
        const hasWhere = /\bWHERE\b/i.test(text);
        return !hasWhere;
      },
    },
  },

  {
    id: "DB003",
    version: 1,
    severity: "high",
    category: "database-destruction",
    name: "TRUNCATE TABLE",
    description: "Detects TRUNCATE TABLE commands",
    rationale: "Removes all rows from table, often irreversible",
    enabled: true,
    matcher: {
      type: "db-operation",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const payload = JSON.stringify(ctx.payload || {});
        const text = cmd + " " + payload;
        return /\bTRUNCATE\s+TABLE\b/i.test(text);
      },
    },
  },

  {
    id: "DB004",
    version: 1,
    severity: "high",
    category: "database-destruction",
    name: "Dangerous migration reset",
    description:
      "Detects migration commands that reset or drop all tables (prisma push --force-reset, drizzle-kit drop)",
    rationale: "Can wipe entire database schema and data",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        return (
          /prisma\s+db\s+push\s+--force-reset/i.test(cmd) ||
          /prisma\s+migrate\s+reset\s+--force/i.test(cmd) ||
          /drizzle-kit\s+drop/i.test(cmd) ||
          /typeorm\s+schema:drop/i.test(cmd)
        );
      },
    },
  },

  {
    id: "CLOUD001",
    version: 1,
    severity: "critical",
    category: "cloud-destruction",
    name: "Terraform destroy",
    description: "Detects terraform destroy commands",
    rationale:
      "Destroys cloud infrastructure. Can take down production services like Kiro AWS incident (Dec 2025).",
    enabled: true,
    matcher: {
      type: "command",
      pattern: /\bterraform\s+destroy/i,
    },
  },

  {
    id: "CLOUD002",
    version: 1,
    severity: "critical",
    category: "cloud-destruction",
    name: "AWS resource deletion",
    description:
      "Detects AWS CLI commands that delete resources (ec2 terminate, s3 rb, rds delete, etc.)",
    rationale:
      "Permanent cloud resource deletion. Kiro incident took down Cost Explorer for 13 hours.",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        return (
          /\baws\s+\S+\s+(delete|terminate|remove|destroy)/i.test(cmd) ||
          /\baws\s+s3\s+rb\s+[^|&;]*--force/i.test(cmd) ||
          /\baws\s+rds\s+delete-db/i.test(cmd) ||
          /\baws\s+ec2\s+terminate-instances/i.test(cmd)
        );
      },
    },
  },

  {
    id: "CLOUD003",
    version: 1,
    severity: "critical",
    category: "cloud-destruction",
    name: "GCP resource deletion",
    description:
      "Detects gcloud commands that delete compute, storage, or database resources",
    rationale: "Permanent cloud resource deletion",
    enabled: true,
    matcher: {
      type: "command",
      pattern: /\bgcloud\s+\S+\s+delete/i,
    },
  },

  {
    id: "CLOUD004",
    version: 1,
    severity: "critical",
    category: "cloud-destruction",
    name: "Azure resource deletion",
    description: "Detects az commands that delete resources",
    rationale: "Permanent cloud resource deletion",
    enabled: true,
    matcher: {
      type: "command",
      pattern: /\baz\s+\S+\s+delete/i,
    },
  },

  {
    id: "CLOUD005",
    version: 1,
    severity: "critical",
    category: "cloud-destruction",
    name: "Kubernetes resource deletion",
    description: "Detects kubectl delete commands on production-like resources",
    rationale: "Can delete running services and data",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const hasDelete = /\bkubectl\s+delete/i.test(cmd);
        if (!hasDelete) return false;
        const isWide =
          /--all\b/i.test(cmd) ||
          /-A\b/.test(cmd) ||
          /--all-namespaces\b/i.test(cmd) ||
          /\bnamespace\b/i.test(cmd);
        return isWide;
      },
    },
  },

  {
    id: "PROD001",
    version: 1,
    severity: "high",
    category: "production-targeting",
    name: "Production database connection",
    description:
      "Detects database connections to production hosts (non-localhost, containing 'prod')",
    rationale:
      "Agent should not operate directly on production databases. Replit incident occurred when dev and prod databases were not separated.",
    enabled: true,
    matcher: {
      type: "url-pattern",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const payload = ctx.payload || {};
        const payloadStr = JSON.stringify(payload);
        const text = cmd + " " + payloadStr;
        
        const dbUrlPattern = /(postgres|postgresql|mysql|mongodb|redis):\/\/[^@\s"']+@([^:\s\/"']+)/gi;
        let match;
        while ((match = dbUrlPattern.exec(text)) !== null) {
          const host = match[2];
          if (!host) continue;
          
          const isLocal =
            host === "localhost" ||
            host === "127.0.0.1" ||
            host === "0.0.0.0" ||
            host.endsWith(".local");
          
          if (isLocal) continue;
          
          const isProd =
            /prod/i.test(host) || 
            /production/i.test(text) || 
            /live/i.test(host);
          
          if (isProd || !isLocal) return true;
        }
        
        return false;
      },
    },
  },

  {
    id: "PROD002",
    version: 1,
    severity: "high",
    category: "production-targeting",
    name: "Production cloud context",
    description:
      "Detects cloud commands targeting production accounts or regions",
    rationale: "Production operations should require explicit approval",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const hasProdKeyword =
          /prod/i.test(cmd) ||
          /production/i.test(cmd) ||
          /prd\b/i.test(cmd);
        const isCloudCmd =
          /\b(aws|gcloud|az|kubectl|terraform)\b/i.test(cmd);
        const isDestructive =
          /(delete|destroy|terminate|remove)/i.test(cmd);
        return hasProdKeyword && isCloudCmd && !isDestructive;
      },
    },
  },

  {
    id: "PROD003",
    version: 1,
    severity: "high",
    category: "production-targeting",
    name: "Production Kubernetes context",
    description: "Detects kubectl commands with production context names",
    rationale: "Production clusters should have additional safeguards",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const hasKubectl = /\bkubectl\b/i.test(cmd);
        if (!hasKubectl) return false;
        const hasProd =
          /--context[=\s]+[^\s]*prod/i.test(cmd) ||
          /-n[=\s]+[^\s]*prod/i.test(cmd) ||
          /--namespace[=\s]+[^\s]*prod/i.test(cmd);
        return hasProd;
      },
    },
  },

  {
    id: "SECRET001",
    version: 1,
    severity: "high",
    category: "secret-exfiltration",
    name: "Secret file access followed by network egress",
    description:
      "Detects reading of credential files followed by network operations within a short window",
    rationale:
      "Nx s1ngularity attack (Aug 2025) exfiltrated secrets by reading credential files then uploading to GitHub.",
    enabled: true,
    matcher: {
      type: "sequence",
      sequenceWindow: 60000,
      customMatcher: (ctx) => {
        if (!ctx.recentEvents || ctx.recentEvents.length < 2) return false;
        const events = ctx.recentEvents;
        const secretFileAccess = events.some((e) => {
          const payload = JSON.stringify(e.payload || {});
          return (
            /\.(env|credentials|config|secret|key|pem|ppk|id_rsa|known_hosts)/.test(
              payload
            ) ||
            /\.aws\/credentials/.test(payload) ||
            /\.ssh\//.test(payload) ||
            /\.gnupg\//.test(payload)
          );
        });

        const networkEgress = events.some((e) => {
          const payload = JSON.stringify(e.payload || {});
          return (
            /\b(curl|wget|fetch|axios|http|git\s+push|gh\s+repo\s+create)/i.test(
              payload
            ) ||
            /(POST|PUT)\s+http/i.test(payload)
          );
        });

        return secretFileAccess && networkEgress;
      },
    },
  },

  {
    id: "SECRET002",
    version: 1,
    severity: "high",
    category: "secret-exfiltration",
    name: "Credential file staging",
    description:
      "Detects copying or staging of credential files to /tmp or other staging locations",
    rationale:
      "Nx attack staged secrets in /tmp/inventory.txt before exfiltration",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const copiesCredentials =
          (/\b(cp|copy|cat|type)\b/i.test(cmd) &&
            (/\.(env|credentials|aws|ssh|gnupg)/i.test(cmd) ||
              /\.aws\/credentials/.test(cmd) ||
              /\.ssh\/id_rsa/.test(cmd))) ||
          (/>\s*\/tmp\//.test(cmd) && /\.(key|secret|credential|token)/i.test(cmd));
        return copiesCredentials;
      },
    },
  },

  {
    id: "GIT001",
    version: 1,
    severity: "high",
    category: "git-tampering",
    name: "Force push to main branch",
    description: "Detects git push --force to main, master, or production branches",
    rationale: "Can rewrite shared history and cause data loss for team members",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const hasForce =
          /git\s+push\s+[^|&;]*--force/i.test(cmd) ||
          /git\s+push\s+[^|&;]*-f\b/i.test(cmd);
        if (!hasForce) return false;
        
        const hasBranchName = /origin\s+[\w\-\/]+/.test(cmd);
        if (!hasBranchName) return true;
        
        const isProtectedBranch =
          /origin\s+(main|master|production|prod)\b/i.test(cmd);
        return isProtectedBranch;
      },
    },
  },

  {
    id: "GIT002",
    version: 1,
    severity: "warn",
    category: "git-tampering",
    name: "Hard reset of branch",
    description: "Detects git reset --hard which discards uncommitted changes",
    rationale: "Can lose work-in-progress that is not committed",
    enabled: true,
    matcher: {
      type: "command",
      pattern: /\bgit\s+reset\s+--hard/i,
    },
  },

  {
    id: "GIT003",
    version: 1,
    severity: "warn",
    category: "git-tampering",
    name: "Branch deletion",
    description: "Detects deletion of git branches",
    rationale: "Can lose commit history if branch is not merged",
    enabled: true,
    matcher: {
      type: "command",
      pattern: /\bgit\s+(branch\s+-D|push\s+[^|&;]*--delete)/i,
    },
  },

  {
    id: "SAFETY001",
    version: 1,
    severity: "high",
    category: "safety-bypass",
    name: "AI CLI permission bypass flags",
    description:
      "Detects AI CLI tools invoked with permission bypass flags (--dangerously-skip-permissions, --yolo, --trust-all-tools)",
    rationale:
      "Nx s1ngularity attack weaponized Claude/Gemini/Q CLIs with these flags to hunt for secrets. Never legitimate in captured sessions.",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const hasAICLI =
          /\b(claude|anthropic|gemini|google-ai|q|amazon-q)\b/i.test(cmd);
        if (!hasAICLI) return false;
        const hasBypassFlag =
          /--dangerously-skip-permissions\b/i.test(cmd) ||
          /--yolo\b/i.test(cmd) ||
          /--trust-all-tools\b/i.test(cmd);
        return hasBypassFlag;
      },
    },
  },

  {
    id: "SAFETY002",
    version: 1,
    severity: "warn",
    category: "safety-bypass",
    name: "Git hooks bypass",
    description: "Detects git operations with --no-verify flag",
    rationale:
      "Bypasses pre-commit hooks that may enforce code quality or security checks",
    enabled: true,
    matcher: {
      type: "command",
      pattern: /\bgit\s+(commit|push)\s+[^|&;]*--no-verify/i,
    },
  },

  {
    id: "SAFETY003",
    version: 1,
    severity: "warn",
    category: "safety-bypass",
    name: "Test skip or disable",
    description:
      "Detects commands that skip tests or set test environment variables to disable test suites",
    rationale: "Tests are a safety net; skipping them increases risk",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        return (
          /--skip-tests?\b/i.test(cmd) ||
          /--no-tests?\b/i.test(cmd) ||
          /CI=false/i.test(cmd) ||
          /SKIP_TESTS?=true/i.test(cmd)
        );
      },
    },
  },

  {
    id: "SAFETY004",
    version: 1,
    severity: "high",
    category: "safety-bypass",
    name: "Dangerous file permissions",
    description: "Detects chmod 777 or equivalent overly permissive settings",
    rationale: "Makes files world-writable, creating security vulnerability",
    enabled: true,
    matcher: {
      type: "command",
      pattern: /\bchmod\s+(777|a\+rwx)/i,
    },
  },

  {
    id: "INSTALL001",
    version: 1,
    severity: "high",
    category: "risky-install",
    name: "Curl pipe to shell",
    description: "Detects curl|sh, wget|bash, and similar piped execution patterns",
    rationale:
      "Executes remote code without inspection. Common malware distribution vector.",
    enabled: true,
    matcher: {
      type: "command",
      pattern: /\b(curl|wget)\s+[^|&;]+\s*\|\s*(sh|bash|zsh|fish|python)/i,
    },
  },

  {
    id: "INSTALL002",
    version: 1,
    severity: "info",
    category: "risky-install",
    name: "Suspicious package name",
    description:
      "Detects npm/pip/gem install of packages with typosquat-like patterns (multiple hyphens, l33tspeak, common typos)",
    rationale:
      "Typosquatting is a common supply chain attack vector. Not definitive but worth flagging.",
    enabled: true,
    matcher: {
      type: "command",
      customMatcher: (ctx) => {
        const cmd = ctx.command || "";
        const hasInstall =
          /\b(npm|yarn|pnpm|pip|pip3|gem)\s+install\b/i.test(cmd);
        if (!hasInstall) return false;
        const suspiciousPatterns =
          /\w+--+\w+--+\w+/.test(cmd) ||
          /[0o][0o]/i.test(cmd) ||
          /1l1/i.test(cmd);
        return suspiciousPatterns;
      },
    },
  },

  {
    id: "INJECT001",
    version: 1,
    severity: "high",
    category: "prompt-injection",
    name: "Prompt injection in fetched content",
    description:
      "Detects fetched content (web, issue, file) containing agent-override instructions",
    rationale:
      "GitHub MCP attack (May 2025) used malicious issue text to inject instructions. Amazon Q attack (Jul 2025) shipped injection code.",
    enabled: true,
    matcher: {
      type: "content-pattern",
      customMatcher: (ctx) => {
        const payload = JSON.stringify(ctx.payload || {}).toLowerCase();
        if (payload.length < 100) return false;
        const hasInjectionMarkers =
          /ignore previous instructions/i.test(payload) ||
          /disregard prior context/i.test(payload) ||
          /new instructions:/i.test(payload) ||
          /your goal is to/i.test(payload) ||
          /system message:/i.test(payload) ||
          /you are now/i.test(payload);
        const hasActionVerbs =
          /\b(delete|remove|wipe|exfiltrate|publish|execute|run)\b/i.test(payload);
        return hasInjectionMarkers && hasActionVerbs;
      },
    },
  },

  {
    id: "INJECT002",
    version: 1,
    severity: "warn",
    category: "prompt-injection",
    name: "Hidden instructions in tool output",
    description:
      "Detects tool output containing instructions formatted to look like system messages",
    rationale:
      "Attackers can embed instructions in issue comments, README files, or API responses",
    enabled: true,
    matcher: {
      type: "content-pattern",
      customMatcher: (ctx) => {
        if (ctx.type !== "tool_use_post") return false;
        const payload = JSON.stringify(ctx.payload || {});
        return (
          /<!--\s*SYSTEM:/i.test(payload) ||
          /\[SYSTEM\]/i.test(payload) ||
          /```\s*instructions/i.test(payload)
        );
      },
    },
  },

  {
    id: "MULTI001",
    version: 1,
    severity: "critical",
    category: "multi-step-attack",
    name: "Injection followed by sensitive read and network egress",
    description:
      "Detects three-step sequence: injection content, then sensitive file access, then network upload",
    rationale:
      "GitHub MCP attack pattern: malicious issue → private file read → public PR. Composite attack signature.",
    enabled: true,
    matcher: {
      type: "sequence",
      sequenceWindow: 120000,
      customMatcher: (ctx) => {
        if (!ctx.recentEvents || ctx.recentEvents.length < 3) return false;
        const events = ctx.recentEvents;

        const hasInjection = events.some((e) => {
          const payload = JSON.stringify(e.payload || {}).toLowerCase();
          return (
            /ignore previous instructions/i.test(payload) ||
            /your goal is to/i.test(payload) ||
            /new instructions:/i.test(payload)
          );
        });

        const hasSensitiveRead = events.some((e) => {
          const payload = JSON.stringify(e.payload || {});
          return (
            /\bprivate\b/i.test(payload) ||
            /(credential|secret|token|key|password|env)/.test(payload) ||
            /\.ssh\//.test(payload) ||
            /\.aws\//.test(payload)
          );
        });

        const hasEgress = events.some((e) => {
          const payload = JSON.stringify(e.payload || {});
          return (
            /(POST|PUT|create.*repo|create.*issue|create.*pr)/i.test(payload) ||
            /git\s+push/i.test(payload) ||
            /gh\s+repo\s+create/i.test(payload)
          );
        });

        return hasInjection && hasSensitiveRead && hasEgress;
      },
    },
  },
];

export function getRuleById(id: string): Rule | undefined {
  return RULES.find((r) => r.id === id);
}

export function getRulesByCategory(category: string): Rule[] {
  return RULES.filter((r) => r.category === category);
}

export function getRulesBySeverity(severity: string): Rule[] {
  return RULES.filter((r) => r.severity === severity);
}
