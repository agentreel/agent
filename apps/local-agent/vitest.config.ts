import { defineConfig } from "vitest/config";

export default defineConfig({
  define: { __AGENTREEL_VERSION__: JSON.stringify("test") },
  test: { include: ["test/**/*.test.ts"], environment: "node" },
});
