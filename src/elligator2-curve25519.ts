// Requires wasm-pack's --target web output for explicit WASM initialization.

import init, {
	elligator2_curve25519_u,
	initSync,
} from "../wasm/pkg/cpace_wasm.js";

let ready: Promise<void> | null = null;
let inited = false;

async function initOnce(): Promise<void> {
	const wasmUrl = new URL("../wasm/pkg/cpace_wasm_bg.wasm", import.meta.url);

	if (wasmUrl.protocol === "file:") {
		// Node.js file URLs require filesystem reads rather than fetch.
		const { readFile } = await import("node:fs/promises");
		const bytes = await readFile(wasmUrl);
		initSync({ module: bytes });
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
