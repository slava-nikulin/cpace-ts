// test/cpace-b1.3.x25519.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { bytesToHex, generatorString, utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import {
	TC_CI,
	TC_G,
	TC_PRS,
	TC_SID,
	TC_YB,
	TC_YB_SCALAR,
} from "./cpace-testvectors-b1";

describe("Appendix B.1.3 — message from B (vectors)", () => {
	it("computes Yb from fixed yb exactly like in the draft", async () => {
		// 1) sanity: generator_string такой же, как в B.1.1
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

		// 2) сам генератор g — сверяем с константой из C-инициализаторов
		const g = await G_X25519.calculateGenerator(sha512, TC_PRS, TC_CI, TC_SID);
		expect(bytesToHex(g)).toBe(bytesToHex(TC_G));

		// 3) yb из драфта (little-endian) — тоже константа
		const yb = TC_YB_SCALAR;

		// 4) считаем публичную точку
		const Yb = await G_X25519.scalarMult(yb, g);

		// 5) сравниваем с официальным вектором
		expect(bytesToHex(Yb)).toBe(bytesToHex(TC_YB));
	});
});
