// test/cpace-integration.ir-roles.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import { bytesToHex, utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

const suite = { name: "CPACE-X25519-SHA512", group: G_X25519, hash: sha512 };

describe("CPace IR roles", () => {
	it.skipIf(!globalThis.crypto || !crypto.subtle)(
		"initiator/responder produce the same ISK with proper ordering",
		async () => {
			const prs = utf8("prs-ir-roles");
			const ada = utf8("ADa");
			const adb = utf8("ADb");

			// A — инициатор, B — респондер
			const A = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "initiator",
				ada,
			});
			const B = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "responder",
				adb,
			});

			const m1 = await A.start();
			const m2 = await B.receive(expectDefined(m1, "A start message"));
			await A.receive(expectDefined(m2, "B response message"));

			expect(bytesToHex(A.exportISK())).toBe(bytesToHex(B.exportISK()));
		},
	);
});
