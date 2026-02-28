import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import { bytesToHex, utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

const suite = { name: "CPACE-X25519-SHA512", group: G_X25519, hash: sha512 };
const HAS_CRYPTO = !!globalThis.crypto && !!crypto.subtle;

function makeSession(
	prs: Uint8Array,
	ad?: Uint8Array,
): CPaceSession {
	return new CPaceSession({
		prs,
		suite,
		mode: "symmetric",
		role: "symmetric",
		...(ad !== undefined ? { ad } : {}),
	});
}

describe("CPace symmetric associated data", () => {
	it.skipIf(!HAS_CRYPTO)(
		"matches ISK when both sides agree on ad",
		async () => {
			const prs = utf8("sym-ad-equal");
			const ad = utf8("ad-shared");

			const A = makeSession(prs, ad);
			const B = makeSession(prs, ad);

			const aMsg = await A.start();
			const bMsg = await B.start();
			await A.receive(expectDefined(bMsg, "B message"));
			await B.receive(expectDefined(aMsg, "A message"));

			expect(bytesToHex(A.exportISK())).toBe(bytesToHex(B.exportISK()));
		},
	);

	it.skipIf(!HAS_CRYPTO)(
		"includes ad on outbound message",
		async () => {
			const prs = utf8("sym-ad-both");
			const ad = utf8("ad-value");
			const session = new CPaceSession({
				prs,
				suite,
				mode: "symmetric",
				role: "symmetric",
				ad,
			});

			const msg = expectDefined(await session.start(), "symmetric message");
			expect(bytesToHex(msg.ad)).toBe(bytesToHex(ad));
		},
	);

	it.skipIf(!HAS_CRYPTO)(
		"matches ISK when sides use different ad values",
		async () => {
			const prs = utf8("sym-ad-mixed");
			const adA = utf8("ad-A");
			const adB = utf8("ad-B");

			const A = makeSession(prs, adA);
			const B = makeSession(prs, adB);

			const aMsg = await A.start();
			const bMsg = await B.start();
			await A.receive(expectDefined(bMsg, "B message"));
			await B.receive(expectDefined(aMsg, "A message"));

			expect(bytesToHex(A.exportISK())).toBe(bytesToHex(B.exportISK()));
		},
	);

	it.skipIf(!HAS_CRYPTO)(
		"matches ISK when one side omits ad",
		async () => {
			const prs = utf8("sym-ad-diff");
			const A = makeSession(prs, utf8("ad-A"));
			const B = makeSession(prs, undefined);
			const aMsg = await A.start();
			const bMsg = await B.start();
			await A.receive(expectDefined(bMsg, "B message"));
			await B.receive(expectDefined(aMsg, "A message"));
			expect(bytesToHex(A.exportISK())).toBe(bytesToHex(B.exportISK()));
		},
	);
});
