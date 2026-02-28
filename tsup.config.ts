import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm", "cjs"],
	dts: true,
	sourcemap: true,
	clean: true,

	// “ES2025” практично = esnext (самый новый таргет у esbuild/tsup)
	target: "esnext",

	// Чтобы вообще не было чанков/внутренних импортов
	splitting: false,

	platform: "node",
	external: ["../wasm/pkg/cpace_wasm.js"],
});
