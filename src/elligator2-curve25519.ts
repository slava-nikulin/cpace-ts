// src/elligator2-curve25519.ts
//
// Invariant: wasm is built with `wasm-pack build --target web` (manual instantiation). [web:13][web:36]
// Vite does not support the "ESM integration proposal for Wasm" used by `--target bundler`. [web:166][web:13]

import init, {
	elligator2_curve25519_u,
	initSync,
} from "../wasm/pkg/cpace_wasm.js";

let ready: Promise<void> | null = null;
let inited = false;

async function initOnce(): Promise<void> {
	const wasmUrl = new URL("../wasm/pkg/cpace_wasm_bg.wasm", import.meta.url);

	if (wasmUrl.protocol === "file:") {
		const { readFile } = await import("node:fs/promises");
		const bytes = await readFile(wasmUrl);
		initSync({ module: bytes }); // sync instantiation from bytes is supported. [web:193]
		return;
	}

	const resp = await fetch(wasmUrl);
	if (!resp.ok)
		throw new Error(`Failed to load WASM: ${resp.status} ${resp.statusText}`);
	await init(resp);
}

export function initElligator2Wasm(): Promise<void> {
	if (inited) return Promise.resolve();

	if (!ready) {
		ready = initOnce()
			.then(() => {
				inited = true;
			})
			.catch((e) => {
				ready = null; // allow retry after transient failure
				inited = false;
				throw e;
			});
	}

	return ready;
}

export async function mapToCurveElligator2(
	u: Uint8Array,
): Promise<Uint8Array> {
	if (u.length !== 32) throw new Error("Expected 32-byte input");
	await initElligator2Wasm();
	return elligator2_curve25519_u(u);
}

export async function mapToCurveElligator2Async(
	u: Uint8Array,
): Promise<Uint8Array> {
	return mapToCurveElligator2(u);
}
