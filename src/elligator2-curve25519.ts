// src/elligator2-curve25519.ts

import { decodeUCoordinate, encodeUCoordinate } from "./rfc7748";

// параметры Curve25519
const P: bigint = (1n << 255n) - 19n; // q
const A_CURVE: bigint = 486662n;
const B_CURVE: bigint = 1n;
const Z_NON_SQUARE: bigint = 2n; // из аппендикса: Z = 2 для Curve25519
const FIELD_BITS = 255;

// (a mod p) с нормализацией в [0, p)
function mod(a: bigint, p: bigint): bigint {
	const r = a % p;
	return r >= 0 ? r : r + p;
}

function modAdd(a: bigint, b: bigint, p: bigint): bigint {
	return mod(a + b, p);
}

function modMul(a: bigint, b: bigint, p: bigint): bigint {
	return mod(a * b, p);
}

// возведение в степень по модулю
function modPow(base: bigint, exp: bigint, p: bigint): bigint {
	let result = 1n;
	let b = mod(base, p);
	let e = exp;
	while (e > 0) {
		if (e & 1n) {
			result = mod(result * b, p);
		}
		b = mod(b * b, p);
		e >>= 1n;
	}
	return result;
}

// обратный элемент: a^{-1} mod p
function modInv(a: bigint, p: bigint): bigint {
	// расширенный евклид
	let t = 0n;
	let newT = 1n;
	let r = p;
	let newR = mod(a, p);

	while (newR !== 0n) {
		const q = r / newR;

		const tmpT = newT;
		newT = t - q * newT;
		t = tmpT;

		const tmpR = newR;
		newR = r - q * newR;
		r = tmpR;
	}

	if (r > 1n) {
		throw new Error("modInv: not invertible");
	}
	if (t < 0n) {
		t = t + p;
	}
	return t;
}

// Elligator2 for Curve25519, по псевдокоду из A.5
// r — элемент поля (у нас это bigint)
export function elligator2Curve25519(r: bigint): Uint8Array {
	const q = P;
	const A = A_CURVE;
	const B = B_CURVE;
	const z = Z_NON_SQUARE;

	// v = - A / (1 + z * r^2)
	const r2 = modMul(r, r, q);
	const denom = modAdd(1n, modMul(z, r2, q), q); // 1 + z*r^2
	const denomInv = modInv(denom, q);
	const v = mod(-A * denomInv, q);

	// epsilon = (v^3 + A*v^2 + B*v) ^ ((q-1)/2)
	const v2 = modMul(v, v, q);
	const v3 = modMul(v2, v, q);

	const term = modAdd(modAdd(v3, modMul(A, v2, q), q), modMul(B, v, q), q);

	const legendreExp = (q - 1n) >> 1n;
	const epsilon = modPow(term, legendreExp, q); // будет 1 или q-1

	// x = epsilon * v - (1 - epsilon) * A/2
	// посчитаем A/2
	const inv2 = modInv(2n, q); // (q+1)/2
	const A_half = modMul(A, inv2, q);

	const oneMinusEps = mod(1n - epsilon, q);
	// eps * v
	const epsV = modMul(epsilon, v, q);
	// (1 - eps) * A/2
	const part = modMul(oneMinusEps, A_half, q);

	const x = mod(epsV - part, q);

	// encoded u-coordinate
	return encodeUCoordinate(x, FIELD_BITS);
}

// обёртка под нашу группу: вход u (32 байта) -> u as FE -> elligator2 -> 32 байта
export function mapToCurveElligator2(u: Uint8Array): Uint8Array {
	const r = decodeUCoordinate(u, FIELD_BITS);
	return elligator2Curve25519(r);
}
