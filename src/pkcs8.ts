// pkcs8.ts

function derLen(n: number): Uint8Array {
	if (n < 0x80) {
		return new Uint8Array([n]);
	}
	const bytes: number[] = [];
	let x = n;
	while (x > 0) {
		bytes.push(x & 0xff);
		x >>= 8;
	}
	bytes.reverse();
	const out = new Uint8Array(1 + bytes.length);
	out[0] = 0x80 | bytes.length;
	out.set(bytes, 1);
	return out;
}

function derSeq(...parts: Uint8Array[]): Uint8Array {
	const len = parts.reduce((acc, p) => acc + p.length, 0);
	const lenEnc = derLen(len);
	const out = new Uint8Array(1 + lenEnc.length + len);
	let offset = 0;

	// tag
	out[offset++] = 0x30;
	// length
	out.set(lenEnc, offset);
	offset += lenEnc.length;
	// parts
	for (const p of parts) {
		out.set(p, offset);
		offset += p.length;
	}

	return out;
}

function derIntZero(): Uint8Array {
	// INTEGER 0
	return new Uint8Array([0x02, 0x01, 0x00]);
}

function derOIDX25519(): Uint8Array {
	// 1.3.101.110 -> 06 03 2B 65 6E
	return new Uint8Array([0x06, 0x03, 0x2b, 0x65, 0x6e]);
}

function derOctet(data: Uint8Array): Uint8Array {
	const lenEnc = derLen(data.length);
	const out = new Uint8Array(1 + lenEnc.length + data.length);
	let offset = 0;
	out[offset++] = 0x04;
	out.set(lenEnc, offset);
	offset += lenEnc.length;
	out.set(data, offset);
	return out;
}

export function pkcs8FromRawX25519Private(raw32: Uint8Array): Uint8Array {
	if (raw32.length !== 32) {
		throw new Error("X25519 private must be 32 bytes");
	}

	// AlgorithmIdentifier ::= SEQUENCE { OID x25519 }
	const algId = derSeq(derOIDX25519());

	// inner OCTET STRING with 32 bytes
	const inner = derOctet(raw32);
	// privateKey (OCTET STRING)
	const privateKey = derOctet(inner);

	// PrivateKeyInfo ::= SEQUENCE { version(0), algId, privateKey }
	return derSeq(derIntZero(), algId, privateKey);
}
