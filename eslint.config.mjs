// ESLint flat config for the agent monorepo.
// Starts from the recommended JS and typescript-eslint rule sets (no type-aware rules, so lint stays fast).
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["**/dist/**", "**/node_modules/**", "**/coverage/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,mts,cts,js,mjs,cjs}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.node },
    },
    linterOptions: {
      reportUnusedDisableDirectives: "warn",
    },
    rules: {
      // Warn for now so this PR stays config-only; tighten to "error" once the existing hits are cleaned up.
      // no-useless-escape: 28 hits, all inside guard and redaction regex literals (src/guard/rules.ts, src/redact/patterns.ts).
      "no-useless-escape": "warn",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },
  {
    // Tests read loosely typed SQLite rows; src stays free of explicit any.
    files: ["**/test/**"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
);
