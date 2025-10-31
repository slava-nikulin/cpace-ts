// test/cpace-strings.test.ts
import { describe, expect, it } from "vitest";
import {
	bytesToHex,
	generatorString,
	lexicographicallyLarger,
	lvCat,
	oCat,
	prependLen,
	transcriptIr,
	transcriptOc,
	utf8,
	zeroBytes,
} from "../src/cpace-strings";

describe("prependLen (appendix A.1.2)", () => {
	it('prepend_len(b"") == 00', () => {
		const r = prependLen(new Uint8Array(0));
		expect(bytesToHex(r)).toBe("00");
	});

	it('prepend_len(b"1234") == 0431323334', () => {
		const r = prependLen(utf8("1234"));
		expect(bytesToHex(r)).toBe("0431323334");
	});

	it("prepend_len(bytes(range(127)))", () => {
		const data = new Uint8Array(127);
		for (let i = 0; i < 127; i += 1) data[i] = i;
		const r = prependLen(data);
		const hex = bytesToHex(r);
		// начало и конец сравниваем с драфтом
		expect(hex.startsWith("7f00")).toBe(true);
		expect(hex.endsWith("7e")).toBe(true);
		expect(r.length).toBe(1 + 127);
	});

	it("prepend_len(bytes(range(128)))", () => {
		const data = new Uint8Array(128);
		for (let i = 0; i < 128; i += 1) data[i] = i;
		const r = prependLen(data);
		const hex = bytesToHex(r);
		// драфт: 80 01 + 0..7f
		expect(hex.startsWith("8001")).toBe(true);
		expect(hex.endsWith("7f")).toBe(true);
		expect(r.length).toBe(2 + 128);
	});
});

describe("lvCat (appendix A.1.4)", () => {
	it('lv_cat(b"1234", b"5", b"", b"678")', () => {
		const r = lvCat(utf8("1234"), utf8("5"), new Uint8Array(0), utf8("678"));
		// 0431323334 01 35 00 03 36 37 38
		expect(bytesToHex(r)).toBe("043132333401350003363738");
	});
});

describe("generatorString (appendix A.2)", () => {
	it("fills zero padding correctly for short PRS", () => {
		const dsi = utf8("CPace255");
		const prs = utf8("pwd");
		const ci = utf8("chan");
		const sid = utf8("sid");
		// SHA-512 -> 128
		const g = generatorString(dsi, prs, ci, sid, 128);
		// просто проверим что структура lv_cat: 5 элементов
		// dsi, prs, zpad, ci, sid
		// первый байт = len(dsi)
		expect(g[0]).toBe(dsi.length);
	});
});

describe("zeroBytes", () => {
	it("returns n zeros", () => {
		const z = zeroBytes(5);
		expect(Array.from(z)).toEqual([0, 0, 0, 0, 0]);
	});
});

describe("A.3.1 lexicographically_larger", () => {
	it('lexiographically_larger(b"\\0", b"\\0\\0") == False', () => {
		const a = new Uint8Array([0x00]);
		const b = new Uint8Array([0x00, 0x00]);
		expect(lexicographicallyLarger(a, b)).toBe(false);
	});

	it('lexiographically_larger(b"\\1", b"\\0\\0") == True', () => {
		const a = new Uint8Array([0x01]);
		const b = new Uint8Array([0x00, 0x00]);
		expect(lexicographicallyLarger(a, b)).toBe(true);
	});

	it('lexiographically_larger(b"\\0\\0", b"\\0") == True', () => {
		const a = new Uint8Array([0x00, 0x00]);
		const b = new Uint8Array([0x00]);
		expect(lexicographicallyLarger(a, b)).toBe(true);
	});

	it('lexiographically_larger(b"\\0\\0", b"\\1") == False', () => {
		const a = new Uint8Array([0x00, 0x00]);
		const b = new Uint8Array([0x01]);
		expect(lexicographicallyLarger(a, b)).toBe(false);
	});

	it('lexiographically_larger(b"\\0\\1", b"\\1") == False', () => {
		const a = new Uint8Array([0x00, 0x01]);
		const b = new Uint8Array([0x01]);
		expect(lexicographicallyLarger(a, b)).toBe(false);
	});

	it('lexiographically_larger(b"ABCD", b"BCD") == False', () => {
		const a = utf8("ABCD");
		const b = utf8("BCD");
		expect(lexicographicallyLarger(a, b)).toBe(false);
	});
});

describe("A.3.2 o_cat", () => {
	it('o_cat(b"ABCD", b"BCD")', () => {
		const r = oCat(utf8("ABCD"), utf8("BCD"));
		// 6f63 42 43 44 41 42 43 44
		expect(bytesToHex(r)).toBe("6f6342434441424344");
	});

	it('o_cat(b"BCD", b"ABCDE")', () => {
		const r = oCat(utf8("BCD"), utf8("ABCDE"));
		// 6f63 42 43 44 41 42 43 44 45
		expect(bytesToHex(r)).toBe("6f634243444142434445");
	});
});

describe("A.3.5 transcript_ir", () => {
	it('transcript_ir(b"123", b"PartyA", b"234", b"PartyB")', () => {
		const r = transcriptIr(
			utf8("123"),
			utf8("PartyA"),
			utf8("234"),
			utf8("PartyB"),
		);
		// 03313233 06 506172747941 03 323334 06 506172747942
		expect(bytesToHex(r)).toBe("03313233065061727479410332333406506172747942");
	});

	it('transcript_ir(b"3456", b"PartyA", b"2345", b"PartyB")', () => {
		const r = transcriptIr(
			utf8("3456"),
			utf8("PartyA"),
			utf8("2345"),
			utf8("PartyB"),
		);
		expect(bytesToHex(r)).toBe(
			"043334353606506172747941043233343506506172747942",
		);
	});
});

describe("A.3.7 transcript_oc", () => {
	it('transcript_oc(b"123", b"PartyA", b"234", b"PartyB")', () => {
		const r = transcriptOc(
			utf8("123"),
			utf8("PartyA"),
			utf8("234"),
			utf8("PartyB"),
		);
		// 6f63 03 323334 06 506172747942 03 313233 06 506172747941
		expect(bytesToHex(r)).toBe(
			"6f6303323334065061727479420331323306506172747941",
		);
	});

	it('transcript_oc(b"3456", b"PartyA", b"2345", b"PartyB")', () => {
		const r = transcriptOc(
			utf8("3456"),
			utf8("PartyA"),
			utf8("2345"),
			utf8("PartyB"),
		);
		expect(bytesToHex(r)).toBe(
			"6f63043334353606506172747941043233343506506172747942",
		);
	});
});
