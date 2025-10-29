import { TextEncoder } from "node:util";
import type { CryptoBackend } from "./crypto-backend";

// HKDF(sharedKey, "room-id") -> roomID
// HKDF(sharedKey, "signal-key") -> aesKey
export interface DerivedKeys {
	roomId: string;
	aesKey: Uint8Array;
}

export async function deriveKeys(
	backend: CryptoBackend,
	sharedKey: Uint8Array,
): Promise<DerivedKeys> {
	const roomInfo = new TextEncoder().encode("room-id");
	const signalInfo = new TextEncoder().encode("signal-key");

	const roomRaw = await backend.hkdf(sharedKey, roomInfo, 16);
	const aesKey = await backend.hkdf(sharedKey, signalInfo, 32);

	// roomID хотим как base64url без паддинга
	const roomId = b64url(roomRaw);

	return { roomId, aesKey };
}

// временная утилита. потом вынесем в utils.ts
function b64url(bytes: Uint8Array): string {
	return Buffer.from(bytes)
		.toString("base64")
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/g, "");
}
