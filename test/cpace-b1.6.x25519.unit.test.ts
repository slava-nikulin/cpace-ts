import { bytesToHex, concatBytes } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import { lvCat, transcriptOc } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import {
	TC_ADA,
	TC_ADB,
	TC_DSI_ISK,
	TC_ISK_INPUT_OC,
	TC_ISK_SY,
	TC_K,
	TC_LV_CAT_DSI_SID_K,
	TC_SID,
	TC_TRANSCRIPT_OC,
	TC_YA,
	TC_YB,
} from "./cpace-testvectors-b1";

describe("Appendix B.1.6 — ISK calculation (parallel / symmetric) — vectors", () => {
	it("reproduces the draft symmetric ISK", async () => {
		const trOc = transcriptOc(TC_YA, TC_ADA, TC_YB, TC_ADB);
		expect(bytesToHex(trOc)).toBe(bytesToHex(TC_TRANSCRIPT_OC));

		const header = lvCat(TC_DSI_ISK, TC_SID, TC_K);
		expect(bytesToHex(header)).toBe(bytesToHex(TC_LV_CAT_DSI_SID_K));

		const material = concatBytes(header, trOc);
		expect(bytesToHex(material)).toBe(bytesToHex(TC_ISK_INPUT_OC));

		const isk = await sha512(material);
		expect(bytesToHex(isk)).toBe(bytesToHex(TC_ISK_SY));
	});
});
