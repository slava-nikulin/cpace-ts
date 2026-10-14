import { bytesToHex } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import { utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

const suite = { name: "CPACE-X25519-SHA512", group: G_X25519, hash: sha512 };

describe("CPace binding — AD changes ISK", () => {
	it.skipIf(!globalThis.crypto || !crypto.subtle)(
		"IR handshakes with different ADa produce different ISKs",
		async () => {
			const prs = utf8("prs-bind-ad");
			const A1 = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "initiator",
				ad: utf8("ADa:v1"),
			});
			const B1 = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "responder",
				ad: utf8("ADb:v1"),
			});
			const m1 = await A1.start();
			const m2 = await B1.receive(expectDefined(m1, "A1 start message"));
			await A1.receive(expectDefined(m2, "B1 response message"));
			const isk1 = A1.exportISK();

			const A2 = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "initiator",
				ad: utf8("ADa:v2"),
			});
			const B2 = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "responder",
				ad: utf8("ADb:v1"),
			});
			const n1 = await A2.start();
			const n2 = await B2.receive(expectDefined(n1, "A2 start message"));
			await A2.receive(expectDefined(n2, "B2 response message"));
			const isk2 = A2.exportISK();

			expect(bytesToHex(isk1)).not.toBe(bytesToHex(isk2));
		},
	);
});
