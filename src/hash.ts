export type HashFn = (input: Uint8Array) => Promise<Uint8Array>;

export async function sha512(input: Uint8Array): Promise<Uint8Array> {
	if (typeof crypto === "undefined" || !crypto.subtle) {
		throw new Error("sha512: WebCrypto SubtleCrypto is not available");
	}
	const digest = await crypto.subtle.digest("SHA-512", input);
	return new Uint8Array(digest);
}
