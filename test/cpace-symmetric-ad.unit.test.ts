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
	ada?: Uint8Array,
	adb?: Uint8Array,
): CPaceSession {
	return new CPaceSession({
		prs,
		suite,
		mode: "symmetric",
		role: "symmetric",
		...(ada !== undefined ? { ada } : {}),
		...(adb !== undefined ? { adb } : {}),
	});
}

describe("CPace symmetric associated data", () => {
	it.skipIf(!HAS_CRYPTO)(
		"matches ISK when both sides agree on ada",
		async () => {
			const prs = utf8("sym-ad-equal");
			const ada = utf8("ada-shared");

			const A = makeSession(prs, ada, undefined);
			const B = makeSession(prs, ada, undefined);

			const aMsg = await A.start();
			const bMsg = await B.start();
			await A.receive(expectDefined(bMsg, "B message"));
			await B.receive(expectDefined(aMsg, "A message"));

			expect(bytesToHex(A.exportISK())).toBe(bytesToHex(B.exportISK()));
		},
	);

	it.skipIf(!HAS_CRYPTO)(
		"rejects configuration that specifies both ada and adb",
		async () => {
			const prs = utf8("sym-ad-both");
			const session = new CPaceSession({
				prs,
				suite,
				mode: "symmetric",
				role: "symmetric",
				ada: utf8("ada"),
				adb: utf8("adb"),
			});

			await expect(session.start()).rejects.toThrow(
				/CPaceSession\.start: symmetric mode accepts either ada or adb/,
			);
		},
	);

	it.skipIf(!HAS_CRYPTO)(
		"matches ISK when one side uses ada and the other uses adb",
		async () => {
			const prs = utf8("sym-ad-mixed");
			const ada = utf8("ada-A");
			const adb = utf8("adb-B");

			const A = makeSession(prs, ada, undefined);
			const B = makeSession(prs, undefined, adb);

			const aMsg = await A.start();
			const bMsg = await B.start();
			await A.receive(expectDefined(bMsg, "B message"));
			await B.receive(expectDefined(aMsg, "A message"));

			expect(bytesToHex(A.exportISK())).toBe(bytesToHex(B.exportISK()));
		},
	);

	it.skipIf(!HAS_CRYPTO)(
		"matches ISK even when ada strings differ",
		async () => {
			const prs = utf8("sym-ad-diff");
			const A = makeSession(prs, utf8("ada-A"), undefined);
			const B = makeSession(prs, utf8("ada-B"), undefined);
			const aMsg = await A.start();
			const bMsg = await B.start();
			await A.receive(expectDefined(bMsg, "B message"));
			await B.receive(expectDefined(aMsg, "A message"));
			expect(bytesToHex(A.exportISK())).toBe(bytesToHex(B.exportISK()));
		},
	);
});
