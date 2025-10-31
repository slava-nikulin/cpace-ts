// test/cpace-b1.4.x25519.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { bytesToHex } from "../src/cpace-strings";
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
		// 1) генератор g из тех же входов, что и в B.1.1
		const g = await G_X25519.calculateGenerator(sha512, TC_PRS, TC_CI, TC_SID);

		// 2) sanity: можно убедиться, что g совпал бы с TC_G
		// (если у тебя TC_G есть в векторах — можно раскомментить)
		// expect(bytesToHex(g)).toBe(bytesToHex(TC_G));

		// 3) секретные скаляры из драфта
		const ya = TC_YA_SCALAR;
		const yb = TC_YB_SCALAR;

		// 4) публичные точки — сверяем с B.1.2 и B.1.3
		const Ya = await G_X25519.scalarMult(ya, g);
		const Yb = await G_X25519.scalarMult(yb, g);

		expect(bytesToHex(Ya)).toBe(bytesToHex(TC_YA));
		expect(bytesToHex(Yb)).toBe(bytesToHex(TC_YB));

		// 5) и сам B.1.4: обе стороны должны получить один и тот же K
		const K1 = await G_X25519.scalarMultVfy(ya, Yb); // A-side
		const K2 = await G_X25519.scalarMultVfy(yb, Ya); // B-side

		expect(bytesToHex(K1)).toBe(bytesToHex(TC_K));
		expect(bytesToHex(K2)).toBe(bytesToHex(TC_K));
	});
});
