import { readFileSync, statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { programOf, segments, tokenize } from "../guard/shell-normalize.js";

/**
 * SQL clients that run a script file (`psql -f drop.sql`, `mysql < drop.sql`)
 * hide the statement from the command text. Before a pre-exec policy check we
 * read those files (regular files only, size-capped) so DB001-DB003 see the
 * SQL that will run.
 */

const SQL_CLIENTS = new Set([
  "psql", "mysql", "mariadb", "sqlite3", "sqlcmd", "cockroach", "duckdb", "clickhouse-client", "pgcli", "mycli",
]);
const FILE_FLAGS = new Set(["-f", "--file", "-i", "--input-file", "--queries-file", "--init"]);

export const SQL_FILE_MAX_BYTES = 256 * 1024;
const MAX_FILES = 4;

export function sqlFileReferences(command: string): string[] {
  if (!command) return [];
  const refs: string[] = [];
  for (const seg of segments(tokenize(command))) {
    const prog = programOf(seg);
    if (!prog || !SQL_CLIENTS.has(prog.name)) continue;
    const args = prog.args;
    for (let i = 0; i < args.length; i++) {
      const a = args[i]!;
      const eq = a.indexOf("=");
      if (a.startsWith("--") && eq > 0 && FILE_FLAGS.has(a.slice(0, eq))) {
        refs.push(a.slice(eq + 1));
      } else if (FILE_FLAGS.has(a) && i + 1 < args.length) {
        refs.push(args[++i]!);
      } else if (/^-f./.test(a)) {
        refs.push(a.slice(2));
      } else if (a === ".read" && i + 1 < args.length) {
        refs.push(args[++i]!);
      } else if (a.startsWith(".read ")) {
        refs.push(a.slice(6).trim());
      }
    }
    for (const input of seg.inputs) refs.push(input);
  }
  return refs.slice(0, MAX_FILES);
}

/** Concatenated contents of the SQL files a command would run. Never throws. */
export function readSqlFileReferences(command: string | undefined, cwd: string | undefined): string | undefined {
  if (!command) return undefined;
  const parts: string[] = [];
  for (const ref of sqlFileReferences(command)) {
    try {
      const full = isAbsolute(ref) ? ref : resolve(cwd ?? process.cwd(), ref);
      const st = statSync(full);
      if (!st.isFile()) continue;
      const buf = readFileSync(full);
      parts.push(buf.subarray(0, SQL_FILE_MAX_BYTES).toString("utf8"));
    } catch {
      // unreadable or missing: nothing to add
    }
  }
  // Whitespace is collapsed so the rules see `DROP TABLE` on one line: in
  // the JSON payload a newline would become "\\n" and glue to the keyword.
  return parts.length > 0 ? parts.join(" ").replace(/\s+/g, " ") : undefined;
}
