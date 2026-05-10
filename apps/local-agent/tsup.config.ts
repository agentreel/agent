import { readFileSync } from "node:fs";
import { defineConfig } from "tsup";

const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8")) as {
  version: string;
};

export default defineConfig({
  entry: { cli: "src/cli.ts" },
  format: ["esm"],
  target: "node20",
  platform: "node",
  outDir: "dist",
  clean: true,
  sourcemap: true,
  shims: false,
  dts: false,
  splitting: false,
  external: ["better-sqlite3"],
  banner: { js: "#!/usr/bin/env node" },
  define: {
    __AGENTREEL_VERSION__: JSON.stringify(pkg.version),
  },
});
