// test/cpace-integration.binding-sid.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import { bytesToHex, utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

const suite = { name: "CPACE-X25519-SHA512", group: G_X25519, hash: sha512 };

describe("CPace binding — sid changes ISK", () => {
	it.skipIf(!globalThis.crypto || !crypto.subtle)(
		"different sid => different ISK (IR mode)",
		async () => {
			const prs = utf8("prs-bind-sid");
			const ci = utf8("CI:ctx");
			const ada = utf8("ADa");
			const adb = utf8("ADb");

			const run = async (sidStr: string) => {
				const A = new CPaceSession({
					prs,
					suite,
					mode: "initiator-responder",
					role: "initiator",
					ci,
					sid: utf8(sidStr),
					ada,
				});
				const B = new CPaceSession({
					prs,
					suite,
					mode: "initiator-responder",
					role: "responder",
					ci,
					sid: utf8(sidStr),
					adb,
				});
				const m1 = await A.start();
				const m2 = await B.receive(expectDefined(m1, "A start message"));
				await A.receive(expectDefined(m2, "B response message"));
				return A.exportISK();
			};

			const i1 = await run("sid#1");
			const i2 = await run("sid#2");

			expect(bytesToHex(i1)).not.toBe(bytesToHex(i2));
		},
	);
});
