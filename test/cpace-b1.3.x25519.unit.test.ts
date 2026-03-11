import { bytesToHex } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { generatorString, utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import {
	TC_CI,
	TC_G,
	TC_GENERATOR_STRING,
	TC_PRS,
	TC_SID,
	TC_YB,
	TC_YB_SCALAR,
} from "./cpace-testvectors-b1";

describe("Appendix B.1.3 — message from B (vectors)", () => {
	it("computes Yb from fixed yb exactly like in the draft", async () => {
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

		const yb = TC_YB_SCALAR;
		const Yb = await G_X25519.scalarMult(yb, g);

		expect(bytesToHex(Yb)).toBe(bytesToHex(TC_YB));
	});
});
