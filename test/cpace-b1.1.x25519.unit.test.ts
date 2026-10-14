import { bytesToHex } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import { generatorString, utf8 } from "../src/cpace-strings";
import { mapToCurveElligator2 } from "../src/elligator2-curve25519";
import { sha512 } from "../src/hash";
import {
	TC_CI,
	TC_DECODED_FIELD_ELEMENT_255,
	TC_G,
	TC_GENERATOR_STRING,
	TC_HASH_GENERATOR_STRING_32,
	TC_PRS,
	TC_SID,
} from "./cpace-testvectors-b1";
import { decodeUCoordinate, encodeUCoordinate } from "./helpers";

describe("Appendix B.1.1 — calculate_generator (X25519, SHA-512)", () => {
	it("reproduces generator_string, its hash32, decoded field element and the final g", async () => {
		const genStr = generatorString(
			utf8("CPace255"),
			TC_PRS,
			TC_CI,
			TC_SID,
			128,
		);

		expect(bytesToHex(genStr)).toBe(bytesToHex(TC_GENERATOR_STRING));

		const digest = await sha512(genStr);
		const h32 = digest.slice(0, 32);
		expect(bytesToHex(h32)).toBe(bytesToHex(TC_HASH_GENERATOR_STRING_32));

		const fe = decodeUCoordinate(h32, 255);
		const decoded = encodeUCoordinate(fe, 255);
		expect(bytesToHex(decoded)).toBe(bytesToHex(TC_DECODED_FIELD_ELEMENT_255));

		const g = await mapToCurveElligator2(h32);
		expect(bytesToHex(g)).toBe(bytesToHex(TC_G));
	});
});
