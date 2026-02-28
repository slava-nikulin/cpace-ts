export function expectDefined<T>(value: T | undefined, label = "value"): T {
	if (value === undefined) {
		throw new Error(`Expected ${label} to be defined`);
	}
	return value;
}

export function decodeLittleEndian(bytes: Uint8Array, bits: number): bigint {
	const len = Math.floor((bits + 7) / 8);
	let out = 0n;
	for (let i = 0; i < len; i += 1) {
		const bi = BigInt(bytes[i] ?? 0);
		out += bi << BigInt(8 * i);
	}
	return out;
}

export function decodeUCoordinate(u: Uint8Array, bits: number): bigint {
	const arr = u.slice();
	if (bits % 8) {
		const last = arr.length - 1;
		const mask = (1 << (bits % 8)) - 1;
		if (arr[last]) {
			arr[last] &= mask;
		}
	}
	return decodeLittleEndian(arr, bits);
}

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
