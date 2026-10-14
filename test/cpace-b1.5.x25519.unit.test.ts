import { bytesToHex, concatBytes } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import {
	generatorString,
	lvCat,
	transcriptIr,
	utf8,
} from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import {
	TC_ADA,
	TC_ADB,
	TC_CI,
	TC_DSI_ISK,
	TC_G,
	TC_GENERATOR_STRING,
	TC_ISK_INPUT_IR,
	TC_ISK_IR,
	TC_K,
	TC_LV_CAT_DSI_SID_K,
	TC_PRS,
	TC_SID,
	TC_TRANSCRIPT_IR,
	TC_YA,
	TC_YA_SCALAR,
	TC_YB,
	TC_YB_SCALAR,
} from "./cpace-testvectors-b1";

describe("Appendix B.1.5 — ISK calculation (initiator/responder) — vectors", () => {
	it("reproduces the draft ISK exactly", async () => {
		const genStr = generatorString(
			utf8("CPace255"),
			TC_PRS,
			TC_CI,
			TC_SID,
			128,
		);
		expect(bytesToHex(genStr)).toBe(bytesToHex(TC_GENERATOR_STRING));

		const g = await G_X25519.calculateGenerator(sha512, TC_PRS, TC_CI, TC_SID);
		expect(bytesToHex(g)).toBe(bytesToHex(TC_G));

		const K1 = await G_X25519.scalarMultVfy(TC_YA_SCALAR, TC_YB);
		const K2 = await G_X25519.scalarMultVfy(TC_YB_SCALAR, TC_YA);
		expect(bytesToHex(K1)).toBe(bytesToHex(TC_K));
		expect(bytesToHex(K2)).toBe(bytesToHex(TC_K));

		const tr = transcriptIr(TC_YA, TC_ADA, TC_YB, TC_ADB);
		expect(bytesToHex(tr)).toBe(bytesToHex(TC_TRANSCRIPT_IR));

		const header = lvCat(TC_DSI_ISK, TC_SID, TC_K);
		expect(bytesToHex(header)).toBe(bytesToHex(TC_LV_CAT_DSI_SID_K));

		const material = concatBytes(header, tr);
		expect(bytesToHex(material)).toBe(bytesToHex(TC_ISK_INPUT_IR));

		const isk = await sha512(material);
		expect(bytesToHex(isk)).toBe(bytesToHex(TC_ISK_IR));
	});
});
