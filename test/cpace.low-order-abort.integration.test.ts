// test/cpace-integration.low-order-abort.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import { utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { TC_U0 } from "./cpace-testvectors-b1-loworder";

const suite = { name: "CPACE-X25519-SHA512", group: G_X25519, hash: sha512 };

describe("CPace abort on low-order peer element", () => {
	it.skipIf(!globalThis.crypto || !crypto.subtle)(
		"receive() aborts when peer sends low-order u-coordinate",
		async () => {
			const prs = utf8("prs-low-order");
			const A = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "initiator",
			});
			const B = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "responder",
			});

			const _aMsg = await A.start(); // нормальное сообщение от A — ок
			await expect(B.receive({ type: "msg", payload: TC_U0 })).rejects.toThrow(
				/invalid peer element/i,
			);
			// Можно прогнать и другие u*: u1,u2,u3,u4,u5,u7...
		},
	);
});
