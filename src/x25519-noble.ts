import { x25519 } from "@noble/curves/ed25519.js";

// The scalar and u-coordinate use 32-byte little-endian encodings.
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

	// Noble clamps the private scalar as specified in RFC 7748.
	const shared = x25519.getSharedSecret(privScalar, pubU);

	if (shared.length !== 32) {
		return shared.slice(0, 32);
	}

	// Reject an all-zero shared secret from a low-order peer input.
	let allZero = true;
	for (let i = 0; i < 32; i++) allZero = allZero && shared[i] === 0;
	if (allZero) {
		throw new Error(
			"x25519Noble: invalid public key (shared secret is all-zero)",
		);
	}

	return shared;
}
