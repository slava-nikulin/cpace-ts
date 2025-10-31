import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		environment: "node",
		typecheck: {
			tsconfig: "./tsconfig.vitest.json",
		},
		projects: [
			{
				test: {
					name: "unit",
					include: ["**/*.unit.{test,spec}.ts?(x)"],
				},
			},
			{
				test: {
					name: "integration",
					include: ["**/*.integration.{test,spec}.ts?(x)"],
				},
			},
		],
	},
});
