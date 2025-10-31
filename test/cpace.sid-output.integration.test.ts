// test/cpace-integration.sid-output.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import {
	bytesToHex,
	concat,
	transcriptIr,
	transcriptOc,
	utf8,
} from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

const suite = { name: "CPACE-X25519-SHA512", group: G_X25519, hash: sha512 };

describe("CPace sidOutput when no input sid", () => {
	it.skipIf(!globalThis.crypto || !crypto.subtle)(
		"IR: sidOutput equals prefix of H('CPaceSidOutput'||transcript_ir)",
		async () => {
			const prs = utf8("prs-sidout-ir");
			const ada = utf8("ADa");
			const adb = utf8("ADb");

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

			// Получаем Ya / Yb из внутренних сообщений:
			const Ya = expectDefined(m1, "A start message").payload;
			const Yb = expectDefined(m2, "B response message").payload;
			const tIR = transcriptIr(Ya, ada, Yb, adb);
			const sidOutRef = await sha512(concat([utf8("CPaceSidOutput"), tIR]));

			// В реализации ты берёшь первые 16 байт ISK в качестве sidValue,
			// но стандартный sidOut — хеш с префиксом "CPaceSidOut".
			// Мы проверим равенство первых 16 байт твоего sidValue и ref-хеша.
			const ref16 = new Uint8Array(sidOutRef.slice(0, 16));
			expect(bytesToHex(expectDefined(A.sidOutput, "A sidOutput"))).toBe(
				bytesToHex(ref16),
			);
			expect(bytesToHex(expectDefined(B.sidOutput, "B sidOutput"))).toBe(
				bytesToHex(ref16),
			);
		},
	);

	it.skipIf(!globalThis.crypto || !crypto.subtle)(
		"Symmetric: sidOutput equals prefix of H('CPaceSidOutput'||transcript_oc)",
		async () => {
			const prs = utf8("prs-sidout-oc");
			const A = new CPaceSession({
				prs,
				suite,
				mode: "symmetric",
				role: "symmetric",
			});
			const B = new CPaceSession({
				prs,
				suite,
				mode: "symmetric",
				role: "symmetric",
			});

			const aMsg = await A.start();
			const bMsg = await B.start();
			await A.receive(expectDefined(bMsg, "B symmetric message"));
			await B.receive(expectDefined(aMsg, "A symmetric message"));

			const tOC = transcriptOc(
				expectDefined(aMsg, "A symmetric message").payload,
				new Uint8Array(0),
				expectDefined(bMsg, "B symmetric message").payload,
				new Uint8Array(0),
			);
			const sidOutRef = await sha512(concat([utf8("CPaceSidOutput"), tOC]));
			const ref16 = new Uint8Array(sidOutRef.slice(0, 16));

			expect(bytesToHex(expectDefined(A.sidOutput, "A sidOutput"))).toBe(
				bytesToHex(ref16),
			);
			expect(bytesToHex(expectDefined(B.sidOutput, "B sidOutput"))).toBe(
				bytesToHex(ref16),
			);
		},
	);
});
