// src/x25519-noble.ts
import { x25519 } from "@noble/curves/ed25519.js";

// приватный: 32 байта (LE), публичный: 32 байта (u)
export function x25519Noble(
	privScalar: Uint8Array,
	pubU: Uint8Array,
): Uint8Array {
	if (privScalar.length !== 32) {
		throw new Error(
			`x25519Noble: privScalar must be 32 bytes, got ${privScalar.length}`,
		);
	}
	if (pubU.length !== 32) {
		throw new Error(`x25519Noble: pubU must be 32 bytes, got ${pubU.length}`);
	}

	// noble сам делает clamp приватного скаляра (как RFC 7748)
	const shared = x25519.getSharedSecret(privScalar, pubU);

	// Для X25519 общий секрет должен быть 32 байта
	if (shared.length !== 32) {
		// на случай, если API/обвязка когда-то вернёт не 32 (маловероятно для x25519)
		return shared.slice(0, 32);
	}

	// Опционально: защита от small-order/invalid public key (all-zero shared secret)
	// (в некоторых протоколах это важно; в PAKE — зависит от конкретной схемы)
	let allZero = true;
	for (let i = 0; i < 32; i++) allZero = allZero && shared[i] === 0;
	if (allZero) {
		throw new Error(
			"x25519Noble: invalid public key (shared secret is all-zero)",
		);
	}

	return shared;
}
