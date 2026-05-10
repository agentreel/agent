import { defineConfig } from "tsup";

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
});
