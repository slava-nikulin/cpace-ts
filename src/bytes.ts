export function compareBytes(a: Uint8Array, b: Uint8Array): number {
	const len = Math.min(a.length, b.length);
	for (let i = 0; i < len; i += 1) {
		const ai = a[i] ?? 0;
		const bi = b[i] ?? 0;
		if (ai !== bi) return ai - bi;
	}
	return a.length - b.length;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i += 1) {
		const ai = a[i] ?? 0;
		const bi = b[i] ?? 0;
		diff |= ai ^ bi;
	}
	return diff === 0;
}
