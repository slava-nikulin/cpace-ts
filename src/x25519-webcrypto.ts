import { pkcs8FromRawX25519Private } from "./pkcs8";

// The scalar and u-coordinate use 32-byte little-endian encodings.
export async function x25519Webcrypto(
	privScalar: Uint8Array,
	pubU: Uint8Array,
): Promise<Uint8Array> {
	if (typeof crypto === "undefined" || !crypto.subtle) {
		throw new Error("x25519Webcrypto: SubtleCrypto is not available");
	}

	// WebCrypto imports X25519 private scalars in PKCS#8 format.
	const pkcs8 = pkcs8FromRawX25519Private(privScalar);
	const privKey = await crypto.subtle.importKey(
		"pkcs8",
		pkcs8,
		{ name: "X25519" },
		false,
		["deriveBits"],
	);

	const pubKey = await crypto.subtle.importKey(
		"raw",
		pubU,
		{ name: "X25519" },
		false,
		[], // Public keys have no key usages.
	);

	const bits = await crypto.subtle.deriveBits(
		{ name: "X25519", public: pubKey },
		privKey,
		256,
	);

	return new Uint8Array(bits);
}
