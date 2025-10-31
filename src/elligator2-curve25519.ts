// src/elligator2-curve25519.ts

import { Field } from "@noble/curves/abstract/modular.js";
import { decodeUCoordinate, encodeUCoordinate } from "./rfc7748";

// параметры Curve25519
const P: bigint = (1n << 255n) - 19n; // модуль поля
const A_CURVE: bigint = 486662n;
const B_CURVE: bigint = 1n;
const Z_NON_SQUARE: bigint = 2n; // несохраняемый элемент, Z = 2 для Curve25519
const FIELD_BITS = 255;

// создаём арифметику над полем GF(P)
const Fp = Field(P);

/**
 * Реализация Elligator‑2 для Curve25519.
 * Вход: r — элемент поля в виде bigint.
 * Выход: u‑координата точки на кривой в формате Uint8Array (32 байта).
 */
export function elligator2Curve25519(r: bigint): Uint8Array {
	// r^2
	const r2 = Fp.mul(r, r);
	// denom = 1 + z * r^2
	const denom = Fp.add(1n, Fp.mul(Z_NON_SQUARE, r2));
	// denomInv = (1 + z * r^2)^−1
	const denomInv = Fp.inv(denom);

	// v = −A / (1 + z*r^2)
	const v = Fp.neg(Fp.mul(A_CURVE, denomInv));

	// v^2, v^3
	const v2 = Fp.mul(v, v);
	const v3 = Fp.mul(v2, v);
	// term = v^3 + A*v^2 + B*v  (Weierstrass RHS)
	const term = Fp.add(Fp.add(v3, Fp.mul(A_CURVE, v2)), Fp.mul(B_CURVE, v));

	// epsilon = term^((p−1)/2) (Legendre символ: 1 или p−1)
	const legendreExp = (P - 1n) >> 1n;
	const epsilon = Fp.pow(term, legendreExp);

	// A/2: делим коэффициент A на 2 в поле
	const A_half = Fp.div(A_CURVE, 2n);

	// x = epsilon * v − (1 − epsilon) * (A/2)
	const epsV = Fp.mul(epsilon, v);
	const oneMinusEps = Fp.sub(1n, epsilon);
	const part = Fp.mul(oneMinusEps, A_half);
	const x = Fp.sub(epsV, part);

	// сериализуем u‑координату в 32‑байтовый массив (младший разряд влево)
	return encodeUCoordinate(x, FIELD_BITS);
}

/**
 * Обёртка для перехода от закодированной u‑координаты к точке на кривой через Elligator‑2.
 * Вход: u (32 байта) → поле → Elligator‑2 → 32‑байтовая u‑координата.
 */
export function mapToCurveElligator2(u: Uint8Array): Uint8Array {
	const r = decodeUCoordinate(u, FIELD_BITS);
	return elligator2Curve25519(r);
}
