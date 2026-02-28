// test/cpace-b1.6.x25519.test.ts
import { describe, expect, it } from "vitest";
import {
	bytesToHex,
	concat,
	lvCat,
	transcriptOc,
	utf8,
} from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import {
	TC_ADA,
	TC_ADB,
	TC_ISK_SY,
	TC_K,
	TC_SID,
	TC_YA,
	TC_YB,
} from "./cpace-testvectors-b1";

describe("Appendix B.1.6 — ISK calculation (parallel / symmetric) — vectors", () => {
	it("reproduces the draft symmetric ISK", async () => {
		// 1) transcript_oc(Ya, ADa, Yb, ADb)
		const trOc = transcriptOc(TC_YA, TC_ADA, TC_YB, TC_ADB);
		expect(bytesToHex(trOc)).toBe(
			"6f632020cda5955f82c4931545bcbf40758ce1010d7db4db2a907013d79c7a8fcf957f03414462201b02dad6dbd29a07b6d28c9e04cb2f184f0734350e32bb7e62ff9dbcfdb63d1503414461",
		);

		// 2) header = lv_cat(DSI_ISK, sid, K)
		const dsiIsk = utf8("CPace255_ISK");
		const header = lvCat(dsiIsk, TC_SID, TC_K);
		expect(bytesToHex(header)).toBe(
			"0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f2c5720f97fdfcfff1c983ed6283856a401de3191ca919902b323c5f950c9703df7297a",
		);

		// 3) материал = header || transcript_oc(...)
		const material = concat([header, trOc]);
		expect(bytesToHex(material)).toBe(
			"0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f2c5720f97fdfcfff1c983ed6283856a401de3191ca919902b323c5f950c9703df7297a" +
				"6f632020cda5955f82c4931545bcbf40758ce1010d7db4db2a907013d79c7a8fcf957f03414462201b02dad6dbd29a07b6d28c9e04cb2f184f0734350e32bb7e62ff9dbcfdb63d1503414461",
		);

		// 4) ISK
		const isk = await sha512(material);
		expect(bytesToHex(isk)).toBe(bytesToHex(TC_ISK_SY));
	});
});
