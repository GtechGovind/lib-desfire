import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default defineConfig({ ignores: ['dist/**', 'node_modules/**'] }, js.configs.recommended, {
  files: ['src/**/*.{ts,tsx}'],
  extends: [tseslint.configs.recommendedTypeChecked, reactHooks.configs.flat.recommended],
  rules: { curly: ['error', 'all'] },
  languageOptions: {
    globals: globals.browser,
    parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
  },
});
