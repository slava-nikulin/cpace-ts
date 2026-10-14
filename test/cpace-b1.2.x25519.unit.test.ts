import { bytesToHex } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { generatorString, utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import {
	TC_CI,
	TC_DECODED_FIELD_ELEMENT_255,
	TC_GENERATOR_STRING,
	TC_HASH_GENERATOR_STRING_32,
	TC_PRS,
	TC_SID,
	TC_YA,
	TC_YA_SCALAR,
} from "./cpace-testvectors-b1";
import { decodeUCoordinate, encodeUCoordinate } from "./helpers";

describe("Appendix B.1.2 — message from A (vectors)", () => {
	it("computes Ya from fixed ya exactly like in the draft", async () => {
		const genStr = generatorString(
			utf8("CPace255"),
			TC_PRS,
			TC_CI,
			TC_SID,
			128,
		);
		expect(bytesToHex(genStr)).toBe(bytesToHex(TC_GENERATOR_STRING));

		const fullHash = await sha512(genStr);
		const h32 = fullHash.slice(0, 32);
		expect(bytesToHex(h32)).toBe(bytesToHex(TC_HASH_GENERATOR_STRING_32));

		const fe = decodeUCoordinate(h32, 255);
		const feBack = encodeUCoordinate(fe, 255);
		expect(bytesToHex(feBack)).toBe(bytesToHex(TC_DECODED_FIELD_ELEMENT_255));

		const g = await G_X25519.calculateGenerator(sha512, TC_PRS, TC_CI, TC_SID);

		const ya = TC_YA_SCALAR;
		const Ya = await G_X25519.scalarMult(ya, g);

		expect(bytesToHex(Ya)).toBe(bytesToHex(TC_YA));
	});
});
