import { describe, expect, it } from "vitest";
import {
	generatorString,
	prependLen,
	utf8,
	zeroBytes,
} from "../src/cpace-strings";

function leb128Decode(buf: Uint8Array, offset: number): [number, number] {
	let result = 0;
	let shift = 0;
	let cursor = offset;
	while (cursor < buf.length) {
		const byte = buf[cursor];
		result |= (byte & 0x7f) << shift;
		cursor += 1;
		if ((byte & 0x80) === 0) {
			break;
		}
		shift += 7;
	}
	return [result, cursor - offset];
}

function unpackLvCat(buf: Uint8Array): Uint8Array[] {
	const parts: Uint8Array[] = [];
	let offset = 0;
	while (offset < buf.length) {
		const [len, lenBytes] = leb128Decode(buf, offset);
		offset += lenBytes;
		const part = buf.slice(offset, offset + len);
		parts.push(part);
		offset += len;
	}
	return parts;
}

describe("generatorString padding behaviour", () => {
	it("pads with the expected number of zero bytes when inputs are short", () => {
		const dsi = utf8("CPace255");
		const prs = utf8("pw");
		const ci = new Uint8Array(0);
		const sid = new Uint8Array(0);
		const sInBytes = 128;

		const gen = generatorString(dsi, prs, ci, sid, sInBytes);

		const parts = unpackLvCat(gen);
		expect(parts).toHaveLength(5);

		const expectedZpadLen = Math.max(
			0,
			sInBytes - 1 - prependLen(prs).length - prependLen(dsi).length,
		);
		expect(parts[2]).toHaveLength(expectedZpadLen);
		expect(parts[3]).toHaveLength(0);
		expect(parts[4]).toHaveLength(0);
		if (expectedZpadLen > 0) {
			expect(parts[2]).toEqual(zeroBytes(expectedZpadLen));
		}
	});

	it("omits zero padding when inputs already fill the hash block", () => {
		const dsi = utf8("CPace255");
		const prs = new Uint8Array(140).fill(0x42);
		const ci = utf8("ci");
		const sid = utf8("sid");
		const sInBytes = 128;

		const gen = generatorString(dsi, prs, ci, sid, sInBytes);
		const parts = unpackLvCat(gen);
		expect(parts).toHaveLength(5);

		const expectedZpadLen = Math.max(
			0,
			sInBytes - 1 - prependLen(prs).length - prependLen(dsi).length,
		);
		expect(expectedZpadLen).toBe(0);
		expect(parts[2]).toHaveLength(0);
	});
});
