// src/x25519-webcrypto.ts
import { pkcs8FromRawX25519Private } from "./pkcs8";

// приватный: 32 байта (LE), публичный: 32 байта (u)
export async function x25519Webcrypto(
	privScalar: Uint8Array,
	pubU: Uint8Array,
): Promise<Uint8Array> {
	if (typeof crypto === "undefined" || !crypto.subtle) {
		throw new Error("x25519Webcrypto: SubtleCrypto is not available");
	}

	// 1) приватный ключ в PKCS#8
	const pkcs8 = pkcs8FromRawX25519Private(privScalar);
	const privKey = await crypto.subtle.importKey(
		"pkcs8",
		pkcs8, // BufferSource
		{ name: "X25519" },
		false,
		["deriveBits"], // для приватного X25519 допустимо deriveBits/deriveKey
	);

	// 2) публичный ключ можно "raw" (32 байта u)
	const pubKey = await crypto.subtle.importKey(
		"raw",
		pubU,
		{ name: "X25519" },
		false,
		[], // публичный ключ не имеет usages
	);

	// 3) derive 256 бит = 32 байта
	const bits = await crypto.subtle.deriveBits(
		{ name: "X25519", public: pubKey },
		privKey,
		256,
	);

	return new Uint8Array(bits);
}
