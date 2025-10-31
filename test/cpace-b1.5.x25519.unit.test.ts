// test/cpace-b1.5.x25519.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import {
	bytesToHex,
	concat,
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
	TC_ISK_IR,
	TC_K,
	TC_PRS,
	TC_SID,
	TC_YA,
	TC_YB,
} from "./cpace-testvectors-b1";

function hexToBytesFixed(hex: string): Uint8Array {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i += 1) {
		out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

function TC_G_X255_DSI(): Uint8Array {
	// это реально просто b"CPace255"
	return utf8("CPace255");
}

describe("Appendix B.1.5 — ISK calculation (initiator/responder) — vectors", () => {
	it("reproduces the draft ISK exactly", async () => {
		// 1) generator_string sanity
		const genStr = generatorString(TC_G_X255_DSI(), TC_PRS, TC_CI, TC_SID, 128);
		expect(genStr.length).toBeGreaterThan(0);
		// но в тестах дальше нам важен именно сам g через реализацию
		const g = await G_X25519.calculateGenerator(sha512, TC_PRS, TC_CI, TC_SID);
		// сверяемся с вектором
		expect(bytesToHex(g)).toBe(
			"64e8099e3ea682cfdc5cb665c057ebb514d06bf23ebc9f743b51b82242327074",
		);

		// 2) публичные точки — СРАЗУ берем из векторов
		const Ya = TC_YA;
		const Yb = TC_YB;

		// 3) общий секрет — тоже из вектора, но проверим что мы его так же считаем
		const K1 = await G_X25519.scalarMultVfy(
			hexToBytesFixed(
				"21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080",
			),
			Yb,
		);
		const K2 = await G_X25519.scalarMultVfy(
			hexToBytesFixed(
				"848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a",
			),
			Ya,
		);
		expect(bytesToHex(K1)).toBe(bytesToHex(TC_K));
		expect(bytesToHex(K2)).toBe(bytesToHex(TC_K));

		// 4) transcript_ir
		const tr = transcriptIr(Ya, TC_ADA, Yb, TC_ADB);
		expect(bytesToHex(tr)).toBe(
			"201b02dad6dbd29a07b6d28c9e04cb2f184f0734350e32bb7e62ff9dbcfdb63d15034144612020cda5955f82c4931545bcbf40758ce1010d7db4db2a907013d79c7a8fcf957f03414462",
		);

		// 5) header = lv_cat(DSI_ISK, sid, K)
		const dsiIsk = utf8("CPace255_ISK");
		const header = lvCat(dsiIsk, TC_SID, TC_K);

		// 6) финальный материал и хеш
		const material = concat([header, tr]);
		const isk = await sha512(material);

		expect(bytesToHex(isk)).toBe(bytesToHex(TC_ISK_IR));
	});
});
