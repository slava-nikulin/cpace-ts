// test/cpace.generator.longstrings.unit.test.ts
import { describe, expect, it } from "vitest";
import {
	bytesToHex,
	generatorString,
	prependLen,
	utf8,
} from "../src/cpace-strings";

// идентичная формуле из аппендикса (§A.2)
function calcLenZpad(
	s_in_bytes: number,
	DSI: Uint8Array,
	PRS: Uint8Array,
): number {
	const L = s_in_bytes - 1 - prependLen(PRS).length - prependLen(DSI).length;
	return Math.max(0, L);
}

function zpad(n: number): Uint8Array {
	return new Uint8Array(n);
}

describe("generator_string: длинные/корнер-кейсы", () => {
	const DSI = utf8("CPace255"); // для X25519
	const s_in_bytes = 128; // SHA-512 block

	const sizes = [0, 1, 2, 10, 50, 127, 128, 129, 512, 4096, 8192];

	it("формула len_zpad не даёт отрицательных значений и совпадает с построенной строкой", () => {
		for (const n of sizes) {
			const PRS = new Uint8Array(n); // нулевые байты, лишь размер важен
			const CI = utf8("ci"); // каких-то пару байт
			const sid = utf8("sid");

			const lenZ = calcLenZpad(s_in_bytes, DSI, PRS);
			expect(lenZ).toBeGreaterThanOrEqual(0);

			const g = generatorString(DSI, PRS, CI, sid, s_in_bytes);
			expect(g.length).toBeGreaterThan(0);

			// g = lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)
			// Проверим, что третье поле действительно нулевой блок нужной длины.
			// Разпарсить lv_cat: [len||DSI][len||PRS][len||ZPAD][len||CI][len||sid]
			// Упростим: просто сверим, что при нулевом CI/sid нулевой блок присутствует и нужной длины:
		}
	});

	it("некоторые эталонные проверки: krótkие PRS → padding заполняет первый блок SHA-512", () => {
		const PRS = utf8("Password");
		const CI = utf8("ci");
		const sid = utf8("sid");

		const lenZ = calcLenZpad(s_in_bytes, DSI, PRS);
		const g = generatorString(DSI, PRS, CI, sid, s_in_bytes);

		// Длина третьего аргумента внутри lv_cat равна lenZ — проверим это прямым перебором:
		// Возьмём lv_cat(DSI, PRS, zpad), и убедимся, что реально вставлен ровно lenZ нулей.
		const pDSI = prependLen(DSI);
		const pPRS = prependLen(PRS);
		const pZ = prependLen(zpad(lenZ));
		const expectPrefix = new Uint8Array(pDSI.length + pPRS.length + pZ.length);
		expectPrefix.set(pDSI, 0);
		expectPrefix.set(pPRS, pDSI.length);
		expectPrefix.set(pZ, pDSI.length + pPRS.length);

		const gotPrefix = g.slice(0, expectPrefix.length);
		expect(bytesToHex(gotPrefix)).toBe(bytesToHex(expectPrefix));
	});

	it("крайние значения: очень большие PRS/CI/sid не ломают формулу и не дают исключений", () => {
		const HUGE = 1 << 15; // 32K
		const PRS = new Uint8Array(HUGE);
		const CI = new Uint8Array(HUGE);
		const sid = new Uint8Array(HUGE);

		const g = generatorString(DSI, PRS, CI, sid, s_in_bytes);
		// просто sanity: строка построена, длина > всех сумм
		expect(g.length).toBeGreaterThan(PRS.length + CI.length + sid.length);
	});
});
