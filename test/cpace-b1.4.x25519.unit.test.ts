import { bytesToHex } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { sha512 } from "../src/hash";
import {
	TC_CI,
	TC_K,
	TC_PRS,
	TC_SID,
	TC_YA,
	TC_YA_SCALAR,
	TC_YB,
	TC_YB_SCALAR,
} from "./cpace-testvectors-b1";

describe("Appendix B.1.4 — secret points K", () => {
	it("scalar_mult_vfy(ya, Yb) and scalar_mult_vfy(yb, Ya) match the draft", async () => {
		const g = await G_X25519.calculateGenerator(sha512, TC_PRS, TC_CI, TC_SID);

		const ya = TC_YA_SCALAR;
		const yb = TC_YB_SCALAR;

		const Ya = await G_X25519.scalarMult(ya, g);
		const Yb = await G_X25519.scalarMult(yb, g);

		expect(bytesToHex(Ya)).toBe(bytesToHex(TC_YA));
		expect(bytesToHex(Yb)).toBe(bytesToHex(TC_YB));

		const K1 = await G_X25519.scalarMultVfy(ya, Yb);
		const K2 = await G_X25519.scalarMultVfy(yb, Ya);

		expect(bytesToHex(K1)).toBe(bytesToHex(TC_K));
		expect(bytesToHex(K2)).toBe(bytesToHex(TC_K));
	});
});
