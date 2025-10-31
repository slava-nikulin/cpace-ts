// test/cpace-integration.symmetric-only-prs.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import { bytesToHex, utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

const suite = { name: "CPACE-X25519-SHA512", group: G_X25519, hash: sha512 };

describe("CPace symmetric — only PRS; order independence", () => {
	it.skipIf(!globalThis.crypto || !crypto.subtle)(
		"same ISK regardless of send order; sidOutput present when no input sid",
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

			// Оба генерят свои сообщения параллельно
			const aMsg = await A.start(); // Ya
			const bMsg = await B.start(); // Yb

			// Вариант 1: A получает первым
			await A.receive(expectDefined(bMsg, "B symmetric message"));
			// Вариант 2: B получает вторым
			await B.receive(expectDefined(aMsg, "A symmetric message"));

			const iskA = A.exportISK();
			const iskB = B.exportISK();

			expect(bytesToHex(iskA)).toBe(bytesToHex(iskB));
			// Без входного sid обе стороны выдают одинаковый публичный sidOutput
			const aSid = expectDefined(A.sidOutput, "A sidOutput");
			const bSid = expectDefined(B.sidOutput, "B sidOutput");
			expect(bytesToHex(aSid)).toBe(bytesToHex(bSid));
			expect(aSid.length).toBeGreaterThan(0);
		},
	);
});
