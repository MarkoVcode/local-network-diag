import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Rust build output. `target/` contains generated JS assets that Tauri
    // embeds; linting them is meaningless and they are not valid standalone JS.
    "target/**",
    "src-tauri/target/**",
    "src-tauri/gen/**",
  ]),
]);

export default eslintConfig;
