// decodeLittleEndian(b, bits):
// return sum([b[i] << 8*i for i in range((bits+7)/8)])
export function decodeLittleEndian(bytes: Uint8Array, bits: number): bigint {
	const len = Math.floor((bits + 7) / 8);
	let out = 0n;
	for (let i = 0; i < len; i += 1) {
		const bi = BigInt(bytes[i] ?? 0);
		out += bi << BigInt(8 * i);
	}
	return out;
}

// decodeUCoordinate(u, bits):
// - копия из A.4 с маскированием лишних бит
export function decodeUCoordinate(u: Uint8Array, bits: number): bigint {
	const arr = u.slice(); // копия
	if (bits % 8) {
		const last = arr.length - 1;
		const mask = (1 << (bits % 8)) - 1;
		if (arr[last]) {
			arr[last] &= mask;
		}
	}
	return decodeLittleEndian(arr, bits);
}

// encodeUCoordinate(u, bits):
// возвращаем little-endian байты длиной (bits+7)/8
export function encodeUCoordinate(u: bigint, bits: number): Uint8Array {
	const len = Math.floor((bits + 7) / 8);
	const out = new Uint8Array(len);
	let x = u;
	for (let i = 0; i < len; i += 1) {
		out[i] = Number(x & 0xffn);
		x >>= 8n;
	}
	return out;
}
