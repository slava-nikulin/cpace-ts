import { describe, expect, it } from "vitest";
import { equalBytes } from "../src/bytes";

describe("equalBytes constant time comparison", () => {
	it("returns true for identical arrays", () => {
		const a = new Uint8Array([1, 2, 3, 4]);
		const b = new Uint8Array([1, 2, 3, 4]);
		expect(equalBytes(a, b)).toBe(true);
	});

	it("returns false when lengths differ", () => {
		const a = new Uint8Array([1, 2, 3]);
		const b = new Uint8Array([1, 2, 3, 4]);
		expect(equalBytes(a, b)).toBe(false);
	});

	it("returns false when the first byte differs", () => {
		const a = new Uint8Array([9, 2, 3, 4]);
		const b = new Uint8Array([1, 2, 3, 4]);
		expect(equalBytes(a, b)).toBe(false);
	});

	it("returns false when a middle byte differs", () => {
		const a = new Uint8Array([1, 2, 9, 4]);
		const b = new Uint8Array([1, 2, 3, 4]);
		expect(equalBytes(a, b)).toBe(false);
	});

	it("returns false when the last byte differs", () => {
		const a = new Uint8Array([1, 2, 3, 9]);
		const b = new Uint8Array([1, 2, 3, 4]);
		expect(equalBytes(a, b)).toBe(false);
	});
});
