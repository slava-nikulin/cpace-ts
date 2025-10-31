// test/cpace-b1.2.x25519.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { bytesToHex, generatorString, utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { decodeUCoordinate, encodeUCoordinate } from "../src/rfc7748";
import {
	TC_CI,
	TC_PRS,
	TC_SID,
	TC_YA,
	TC_YA_SCALAR,
} from "./cpace-testvectors-b1";

describe("Appendix B.1.2 — message from A (vectors)", () => {
	it("computes Ya from fixed ya exactly like in the draft", async () => {
		// 1) generator_string(DSI, PRS, CI, sid, 128)
		const genStr = generatorString(
			utf8("CPace255"),
			TC_PRS,
			TC_CI,
			TC_SID,
			128,
		);
		expect(bytesToHex(genStr)).toBe(
			"0843506163653235350850617373776f72646d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a6f630b425f726573706f6e6465720b415f696e69746961746f72107e4b4791d6a8ef019b936c79fb7f2c57",
		);

		// 2) SHA-512 и первые 32 байта — в драфте это явно показано
		const fullHash = await sha512(genStr);
		const h32 = fullHash.slice(0, 32);
		expect(bytesToHex(h32)).toBe(
			"92806dc608984dbf4e4aae478c6ec453ae979cc01ecc1a2a7cf49f5cee56551b",
		);

		// 2a) sanity: decodeUCoordinate / encodeUCoordinate
		const fe = decodeUCoordinate(h32, 255);
		const feBack = encodeUCoordinate(fe, 255);
		expect(bytesToHex(feBack)).toBe(bytesToHex(h32));

		// 3) реальный генератор g (через Elligator2), как требует §7.2
		const g = await G_X25519.calculateGenerator(sha512, TC_PRS, TC_CI, TC_SID);

		// 4) приватный скаляр ya из вектора B.1.2
		const ya = TC_YA_SCALAR;

		// 5) публичная точка Ya = ya * g
		const Ya = await G_X25519.scalarMult(ya, g);

		// 6) сверяем с B.1.2
		expect(bytesToHex(Ya)).toBe(bytesToHex(TC_YA));
	});
});
