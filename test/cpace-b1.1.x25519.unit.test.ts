// test/cpace-b1.1.x25519.test.ts
import { describe, expect, it } from "vitest";
import { bytesToHex, generatorString, utf8 } from "../src/cpace-strings";
import { mapToCurveElligator2 } from "../src/elligator2-curve25519";
import { sha512 } from "../src/hash";
import { TC_CI, TC_G, TC_PRS, TC_SID } from "./cpace-testvectors-b1";

describe("Appendix B.1.1 — calculate_generator (X25519, SHA-512)", () => {
	it("reproduces generator_string, its hash32 and the final g", async () => {
		// 1) generator_string(...)
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

		// 2) SHA-512(genStr) → первые 32 байта
		const digest = await sha512(genStr);
		const h32 = digest.slice(0, 32);
		expect(bytesToHex(h32)).toBe(
			"92806dc608984dbf4e4aae478c6ec453ae979cc01ecc1a2a7cf49f5cee56551b",
		);

		// 3) Elligator2 → g
		const g = mapToCurveElligator2(h32);
		expect(bytesToHex(g)).toBe(bytesToHex(TC_G));
	});
});
