import { describe, expect, it } from "vitest";
import { G_X25519, LowOrderPointError } from "../src/cpace-group-x25519";
import { bytesToHex } from "../src/cpace-strings";

import {
	TC_LOW_S,
	TC_Q6,
	TC_Q8,
	TC_Q9,
	TC_QA,
	TC_QB,
	TC_U0,
	TC_U1,
	TC_U2,
	TC_U3,
	TC_U4,
	TC_U5,
	TC_U6,
	TC_U7,
	TC_U8,
	TC_U9,
	TC_UA,
	TC_UB,
} from "./cpace-testvectors-b1-loworder";

describe("Appendix B.1.10 — G_X25519.scalar_mult_vfy low-order / invalid points", () => {
	it("rejects low-order inputs", async () => {
		const lowOrderInputs: Array<[string, Uint8Array]> = [
			["U0", TC_U0],
			["U1", TC_U1],
			["U2", TC_U2],
			["U3", TC_U3],
			["U4", TC_U4],
			["U5", TC_U5],
			["U7", TC_U7],
		];

		for (const [label, u] of lowOrderInputs) {
			await expect(
				G_X25519.scalarMultVfy(TC_LOW_S, u),
				`Expected ${label} to be rejected`,
			).rejects.toBeInstanceOf(LowOrderPointError);
		}
	});

	it("returns the draft qN outputs for non-low-order inputs", async () => {
		const cases: Array<[Uint8Array, Uint8Array]> = [
			[TC_U6, TC_Q6],
			[TC_U8, TC_Q8],
			[TC_U9, TC_Q9],
			[TC_UA, TC_QA],
			[TC_UB, TC_QB],
		];

		for (const [u, q] of cases) {
			const result = await G_X25519.scalarMultVfy(TC_LOW_S, u);
			expect(bytesToHex(result)).toBe(bytesToHex(q));
		}
	});
});
