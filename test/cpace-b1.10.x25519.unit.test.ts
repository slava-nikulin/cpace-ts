import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { bytesToHex } from "../src/cpace-strings";

import {
	TC_LOW_S,
	TC_Q0,
	TC_Q1,
	TC_Q2,
	TC_Q3,
	TC_Q4,
	TC_Q5,
	TC_Q6,
	TC_Q7,
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
	it("returns exactly the qN from the draft", async () => {
		const r0 = await G_X25519.scalarMultVfy(TC_LOW_S, TC_U0);
		expect(bytesToHex(r0)).toBe(bytesToHex(TC_Q0));

		const r1 = await G_X25519.scalarMultVfy(TC_LOW_S, TC_U1);
		expect(bytesToHex(r1)).toBe(bytesToHex(TC_Q1));

		const r2 = await G_X25519.scalarMultVfy(TC_LOW_S, TC_U2);
		expect(bytesToHex(r2)).toBe(bytesToHex(TC_Q2));

		const r3 = await G_X25519.scalarMultVfy(TC_LOW_S, TC_U3);
		expect(bytesToHex(r3)).toBe(bytesToHex(TC_Q3));

		const r4 = await G_X25519.scalarMultVfy(TC_LOW_S, TC_U4);
		expect(bytesToHex(r4)).toBe(bytesToHex(TC_Q4));

		const r5 = await G_X25519.scalarMultVfy(TC_LOW_S, TC_U5);
		expect(bytesToHex(r5)).toBe(bytesToHex(TC_Q5));

		const r6 = await G_X25519.scalarMultVfy(TC_LOW_S, TC_U6);
		expect(bytesToHex(r6)).toBe(bytesToHex(TC_Q6));

		const r7 = await G_X25519.scalarMultVfy(TC_LOW_S, TC_U7);
		expect(bytesToHex(r7)).toBe(bytesToHex(TC_Q7));

		const r8 = await G_X25519.scalarMultVfy(TC_LOW_S, TC_U8);
		expect(bytesToHex(r8)).toBe(bytesToHex(TC_Q8));

		const r9 = await G_X25519.scalarMultVfy(TC_LOW_S, TC_U9);
		expect(bytesToHex(r9)).toBe(bytesToHex(TC_Q9));

		const rA = await G_X25519.scalarMultVfy(TC_LOW_S, TC_UA);
		expect(bytesToHex(rA)).toBe(bytesToHex(TC_QA));

		const rB = await G_X25519.scalarMultVfy(TC_LOW_S, TC_UB);
		expect(bytesToHex(rB)).toBe(bytesToHex(TC_QB));
	});
});
