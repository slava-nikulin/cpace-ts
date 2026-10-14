import { bytesToHex } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import { utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

const suite = { name: "CPACE-X25519-SHA512", group: G_X25519, hash: sha512 };

describe("CPace symmetric mode with only PRS", () => {
	it.skipIf(!globalThis.crypto || !crypto.subtle)(
		"peers derive matching ISKs and sid outputs without optional inputs",
		async () => {
			const PRS = utf8("symmetric-only-prs");

			const A = new CPaceSession({
				prs: PRS,
				suite,
				mode: "symmetric",
				role: "symmetric",
			});
			const B = new CPaceSession({
				prs: PRS,
				suite,
				mode: "symmetric",
				role: "symmetric",
			});

			const aMsg = await A.start();
			const bMsg = await B.start();

			await A.receive(expectDefined(bMsg, "B symmetric message"));
			await B.receive(expectDefined(aMsg, "A symmetric message"));

			const iskA = A.exportISK();
			const iskB = B.exportISK();

			expect(bytesToHex(iskA)).toBe(bytesToHex(iskB));
			const aSid = expectDefined(A.sidOutput, "A sidOutput");
			const bSid = expectDefined(B.sidOutput, "B sidOutput");
			expect(bytesToHex(aSid)).toBe(bytesToHex(bSid));
			expect(aSid.length).toBeGreaterThan(0);
		},
	);
});
