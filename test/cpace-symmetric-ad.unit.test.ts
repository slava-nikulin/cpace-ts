import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import { bytesToHex, utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

const suite = { name: "CPACE-X25519-SHA512", group: G_X25519, hash: sha512 };

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
		ada,
		adb,
	});
}

describe("CPace symmetric associated data", () => {
	it("matches ISK when both sides agree on ada/adb", async () => {
		const prs = utf8("sym-ad-equal");
		const ada = utf8("ada-shared");
		const adb = utf8("adb-shared");

		const A = makeSession(prs, ada, adb);
		const B = makeSession(prs, ada, adb);

		const aMsg = await A.start();
		const bMsg = await B.start();
		await A.receive(expectDefined(bMsg, "B message"));
		await B.receive(expectDefined(aMsg, "A message"));

		const iskA = A.exportISK();
		const iskB = B.exportISK();
		expect(bytesToHex(iskA)).toBe(bytesToHex(iskB));
	});

	it("produces a different ISK when AD values change", async () => {
		const prs = utf8("sym-ad-diff");

		const baseline = makeSession(prs, utf8("ada-base"), utf8("adb-base"));
		const baselinePeer = makeSession(prs, utf8("ada-base"), utf8("adb-base"));
		const baseMsgA = await baseline.start();
		const baseMsgB = await baselinePeer.start();
		await baseline.receive(expectDefined(baseMsgB, "baseline peer message"));
		await baselinePeer.receive(
			expectDefined(baseMsgA, "baseline local message"),
		);
		const baseKey = baseline.exportISK();
		const basePeerKey = baselinePeer.exportISK();
		expect(bytesToHex(baseKey)).toBe(bytesToHex(basePeerKey));

		const A = makeSession(prs, utf8("ada-A"), utf8("adb-A"));
		const B = makeSession(prs, utf8("ada-B"), utf8("adb-B"));
		const aMsg = await A.start();
		const bMsg = await B.start();
		await A.receive(expectDefined(bMsg, "B message"));
		await B.receive(expectDefined(aMsg, "A message"));

		const iskA = A.exportISK();
		const iskB = B.exportISK();
		expect(bytesToHex(iskA)).toBe(bytesToHex(iskB));
		expect(bytesToHex(iskA)).not.toBe(bytesToHex(baseKey));
	});
});
