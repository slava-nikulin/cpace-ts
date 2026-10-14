import { defineConfig } from "tsup";

export default defineConfig({
	entry: ["src/index.ts"],
	format: ["esm", "cjs"],
	shims: true,
	dts: true,
	sourcemap: true,
	clean: true,

	target: "esnext",

	splitting: false,

	platform: "node",
	external: ["../wasm/pkg/cpace_wasm.js"],
});
