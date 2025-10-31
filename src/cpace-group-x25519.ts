// src/x25519.ts
import { randomBytes } from "node:crypto";
import { compareBytes } from "./bytes";
import { generatorString, utf8 } from "./cpace-strings";
import { mapToCurveElligator2 } from "./elligator2-curve25519";
import type { HashFn } from "./hash";
import { x25519Webcrypto } from "./x25519-webcrypto";

export interface GroupEnv {
	name: string;
	fieldSizeBytes: number;
	fieldSizeBits: number;
	sInBytes: number;
	calculateGenerator(
		hash: HashFn,
		prs: Uint8Array,
		ci?: Uint8Array,
		sid?: Uint8Array,
	): Promise<Uint8Array>;
	sampleScalar(): Uint8Array;
	scalarMult(scalar: Uint8Array, point: Uint8Array): Promise<Uint8Array>;
	scalarMultVfy(scalar: Uint8Array, point: Uint8Array): Promise<Uint8Array>;
	I: Uint8Array;
	DSI: Uint8Array;
	serialize(point: Uint8Array): Uint8Array;
	deserialize(buf: Uint8Array): Uint8Array;
}

// общий helper
function getRandomBytes(len: number): Uint8Array {
	const out = new Uint8Array(len);
	if (typeof crypto !== "undefined" && "getRandomValues" in crypto) {
		crypto.getRandomValues(out);
		return out;
	}
	const rb = randomBytes(len);
	out.set(rb);
	return out;
}

// общий x25519 wrapper — одна точка входа
async function x25519(
	scalar: Uint8Array,
	point: Uint8Array,
): Promise<Uint8Array> {
	// сейчас — через WebCrypto
	return x25519Webcrypto(scalar, point);
}

export class LowOrderPointError extends Error {
	constructor(
		message = "X25519Group.scalarMultVfy: low-order or invalid point",
		options?: ErrorOptions,
	) {
		super(message, options);
		this.name = "LowOrderPointError";
	}
}

export class X25519Group implements GroupEnv {
	readonly name = "X25519";
	readonly fieldSizeBytes = 32;
	readonly fieldSizeBits = 255;
	// для SHA-512 (128 байт блок)
	readonly sInBytes = 128;
	readonly DSI = utf8("CPace255");
	// нейтральный элемент (0^32)
	readonly I = new Uint8Array(32);

	async calculateGenerator(
		hash: HashFn,
		prs: Uint8Array,
		ci?: Uint8Array,
		sid?: Uint8Array,
	): Promise<Uint8Array> {
		const genStr = generatorString(this.DSI, prs, ci, sid, this.sInBytes);
		const h = await hash(genStr);
		if (h.length < this.fieldSizeBytes) {
			throw new Error("X25519Group.calculateGenerator: hash output too short");
		}
		const genStrHash = h.slice(0, this.fieldSizeBytes);
		const g = mapToCurveElligator2(genStrHash);
		return this.serialize(g);
	}

	sampleScalar(): Uint8Array {
		return getRandomBytes(this.fieldSizeBytes);
	}

	async scalarMult(scalar: Uint8Array, point: Uint8Array): Promise<Uint8Array> {
		return x25519(scalar, point);
	}

	async scalarMultVfy(
		scalar: Uint8Array,
		point: Uint8Array,
	): Promise<Uint8Array> {
		const u = point.slice();
		if (u.length === 0) {
			throw new LowOrderPointError(
				"X25519Group.scalarMultVfy: invalid point length (zero)",
			);
		}
		// RFC 7748 §5: inputs are interpreted modulo p with the unused MSB cleared.
		const inputLastIndex = u.length - 1;
		const inputLastByte = u[inputLastIndex];
		if (inputLastByte === undefined) {
			throw new LowOrderPointError(
				"X25519Group.scalarMultVfy: invalid point length",
			);
		}
		u[inputLastIndex] = inputLastByte & 0x7f;

		let r: Uint8Array;
		try {
			r = await x25519(scalar, u);
		} catch (err) {
			throw new LowOrderPointError(
				"X25519Group.scalarMultVfy: invalid point multiplication failed",
				{ cause: err },
			);
		}

		if (compareBytes(r, this.I) === 0) {
			throw new LowOrderPointError(
				"X25519Group.scalarMultVfy: low-order result (all-zero shared secret)",
			);
		}

		// RFC 7748 §5: clear the unused most significant bit before returning.
		const masked = r.slice();
		if (masked.length === 0) {
			throw new LowOrderPointError(
				"X25519Group.scalarMultVfy: invalid shared secret length (zero)",
			);
		}
		const outputLastIndex = masked.length - 1;
		const outputLastByte = masked[outputLastIndex];
		if (outputLastByte === undefined) {
			throw new LowOrderPointError(
				"X25519Group.scalarMultVfy: invalid shared secret length",
			);
		}
		masked[outputLastIndex] = outputLastByte & 0x7f;

		return masked;
	}

	serialize(point: Uint8Array): Uint8Array {
		if (point.length !== this.fieldSizeBytes) {
			throw new Error("X25519Group.serialize: bad length");
		}
		return point.slice();
	}

	deserialize(buf: Uint8Array): Uint8Array {
		if (buf.length !== this.fieldSizeBytes) {
			throw new Error("X25519Group.deserialize: bad length");
		}
		return buf.slice();
	}
}

export const G_X25519 = new X25519Group();
