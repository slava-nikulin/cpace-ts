export interface CryptoBackend {
	hkdf(
		inputKeyMaterial: Uint8Array,
		info: Uint8Array,
		length: number,
	): Promise<Uint8Array>;
}
