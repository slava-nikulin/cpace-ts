import { describe, expect, it } from "vitest";
import { generatorString, prependLen, utf8 } from "../src/cpace-strings";
import { bytesToHex } from "@noble/curves/utils.js";

// Padding length from CPace Appendix A.2.
function calcLenZpad(
	s_in_bytes: number,
	DSI: Uint8Array,
	PRS: Uint8Array,
): number {
	const L = s_in_bytes - 1 - prependLen(PRS).length - prependLen(DSI).length;
	return Math.max(0, L);
}

function zpad(n: number): Uint8Array {
	return new Uint8Array(n);
}

describe("generatorString length edge cases", () => {
	const DSI = utf8("CPace255");
	const s_in_bytes = 128; // SHA-512 block

	const sizes = [0, 1, 2, 10, 50, 127, 128, 129, 512, 4096, 8192];

	it("keeps padding lengths non-negative across PRS sizes", () => {
		for (const n of sizes) {
			const PRS = new Uint8Array(n);
			const CI = utf8("ci");
			const sid = utf8("sid");

			const lenZ = calcLenZpad(s_in_bytes, DSI, PRS);
			expect(lenZ).toBeGreaterThanOrEqual(0);

			const g = generatorString(DSI, PRS, CI, sid, s_in_bytes);
			expect(g.length).toBeGreaterThan(0);
		}
	});

	it("includes the expected zero-padding prefix for a short PRS", () => {
		const PRS = utf8("Password");
		const CI = utf8("ci");
		const sid = utf8("sid");

		const lenZ = calcLenZpad(s_in_bytes, DSI, PRS);
		const g = generatorString(DSI, PRS, CI, sid, s_in_bytes);

		const pDSI = prependLen(DSI);
		const pPRS = prependLen(PRS);
		const pZ = prependLen(zpad(lenZ));
		const expectPrefix = new Uint8Array(pDSI.length + pPRS.length + pZ.length);
		expectPrefix.set(pDSI, 0);
		expectPrefix.set(pPRS, pDSI.length);
		expectPrefix.set(pZ, pDSI.length + pPRS.length);

		const gotPrefix = g.slice(0, expectPrefix.length);
		expect(bytesToHex(gotPrefix)).toBe(bytesToHex(expectPrefix));
	});

	it("constructs a generator string from 32 KiB PRS, CI, and sid values", () => {
		const HUGE = 1 << 15;
		const PRS = new Uint8Array(HUGE);
		const CI = new Uint8Array(HUGE);
		const sid = new Uint8Array(HUGE);

		const g = generatorString(DSI, PRS, CI, sid, s_in_bytes);
		expect(g.length).toBeGreaterThan(PRS.length + CI.length + sid.length);
	});
});
