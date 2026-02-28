// test/cpace-b1.7.x25519.test.ts
import { describe, expect, it } from "vitest";
import {
	bytesToHex,
	concat,
	transcriptIr,
	transcriptOc,
	utf8,
} from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import {
	TC_ADA,
	TC_ADB,
	TC_SID_OUT_IR,
	TC_SID_OUT_OC,
	TC_YA,
	TC_YB,
} from "./cpace-testvectors-b1";

describe("Appendix B.1.7 — optional session id output (using C vectors)", () => {
	it("reproduces sid_out for IR from the draft", async () => {
		const tIR = transcriptIr(TC_YA, TC_ADA, TC_YB, TC_ADB);
		const digest = await sha512(concat([utf8("CPaceSidOutput"), tIR]));

		expect(bytesToHex(digest)).toBe(bytesToHex(TC_SID_OUT_IR));
	});

	it("reproduces sid_out for OC from the draft", async () => {
		const tOC = transcriptOc(TC_YA, TC_ADA, TC_YB, TC_ADB);
		const digest = await sha512(concat([utf8("CPaceSidOutput"), tOC]));

		expect(bytesToHex(digest)).toBe(bytesToHex(TC_SID_OUT_OC));
	});
});
