const textEncoder = new TextEncoder();

export function utf8(value: string): Uint8Array {
	return textEncoder.encode(value);
}

export function leb128Encode(n: number): Uint8Array {
	const bytes: number[] = [];
	let v = n >>> 0;
	while (true) {
		if (v < 128) {
			bytes.push(v);
		} else {
			bytes.push((v & 0x7f) + 0x80);
		}
		v = v >>> 7;
		if (v === 0) {
			break;
		}
	}
	return new Uint8Array(bytes);
}

// A.1.1
export function prependLen(data: Uint8Array): Uint8Array {
	const lenEnc = leb128Encode(data.length);
	const out = new Uint8Array(lenEnc.length + data.length);
	out.set(lenEnc, 0);
	out.set(data, lenEnc.length);
	return out;
}

// A.1.3
export function lvCat(...parts: Uint8Array[]): Uint8Array {
	let total = 0;
	const prepped: Uint8Array[] = [];
	for (const p of parts) {
		const withLen = prependLen(p);
		prepped.push(withLen);
		total += withLen.length;
	}
	const out = new Uint8Array(total);
	let off = 0;
	for (const w of prepped) {
		out.set(w, off);
		off += w.length;
	}
	return out;
}

export function zeroBytes(n: number): Uint8Array {
	return new Uint8Array(n);
}

// A.2
export function generatorString(
	dsi: Uint8Array,
	prs: Uint8Array,
	ci: Uint8Array | undefined,
	sid: Uint8Array | undefined,
	sInBytes: number,
): Uint8Array {
	const prsPl = prependLen(prs);
	const dsiPl = prependLen(dsi);
	const lenZpad = Math.max(0, sInBytes - 1 - prsPl.length - dsiPl.length);
	const zpad = zeroBytes(lenZpad);
	return lvCat(
		dsi,
		prs,
		zpad,
		ci ?? new Uint8Array(0),
		sid ?? new Uint8Array(0),
	);
}

export function bytesToHex(u: Uint8Array): string {
	return Array.from(u)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

// =========================
// A.3 ordered concatenation
// =========================

// A.3.1
export function lexicographicallyLarger(
	bytes1: Uint8Array,
	bytes2: Uint8Array,
): boolean {
	const minLen = Math.min(bytes1.length, bytes2.length);
	for (let i = 0; i < minLen; i += 1) {
		const b1 = bytes1[i] as number;
		const b2 = bytes2[i] as number;
		if (b1 > b2) {
			return true;
		} else if (b1 < b2) {
			return false;
		}
	}
	return bytes1.length > bytes2.length;
}

// A.3.2
export function oCat(bytes1: Uint8Array, bytes2: Uint8Array): Uint8Array {
	if (lexicographicallyLarger(bytes1, bytes2)) {
		return concat([utf8("oc"), bytes1, bytes2]);
	}
	return concat([utf8("oc"), bytes2, bytes1]);
}

// A.3.4
export function transcriptIr(
	ya: Uint8Array,
	ada: Uint8Array,
	yb: Uint8Array,
	adb: Uint8Array,
): Uint8Array {
	const left = lvCat(ya, ada);
	const right = lvCat(yb, adb);
	return concat([left, right]);
}

// A.3.6
export function transcriptOc(
	ya: Uint8Array,
	ada: Uint8Array,
	yb: Uint8Array,
	adb: Uint8Array,
): Uint8Array {
	const left = lvCat(ya, ada);
	const right = lvCat(yb, adb);
	return oCat(left, right);
}

// общий concat, чтобы не дублировать
export function concat(chunks: Uint8Array[]): Uint8Array {
	let total = 0;
	for (const c of chunks) total += c.length;
	const out = new Uint8Array(total);
	let off = 0;
	for (const c of chunks) {
		out.set(c, off);
		off += c.length;
	}
	return out;
}
