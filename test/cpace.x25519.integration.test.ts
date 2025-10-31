import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import type { CPaceSuiteDesc } from "../src/cpace-session";
import { CPaceSession } from "../src/cpace-session";
import { bytesToHex, utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

// Базовый suite
const suite: CPaceSuiteDesc = {
	name: "CPACE-X25519-SHA512",
	group: G_X25519,
	hash: sha512,
};

function hex(s: string): Uint8Array {
	const out = new Uint8Array(s.length / 2);
	for (let i = 0; i < out.length; i++)
		out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
	return out;
}

describe("CPace integration — X25519+SHA-512", () => {
	it("IR happy path (оба знают PRS, есть CI/sid/AD): ISK совпадает, sidOutput=given sid", async () => {
		const prs = utf8("Password");
		const ci = utf8("oc\u000bB_responder\u000bA_initiator"); // тот же CI из векторов
		const sid = hex("7e4b4791d6a8ef019b936c79fb7f2c57");

		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ada: utf8("ADa"),
		});
		const b = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			adb: utf8("ADb"),
		});

		const aMsg = expectDefined(await a.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await b.receive(aMsg),
			"responder handshake message",
		);
		await a.receive(bMsg);

		const iskA = a.exportISK();
		const iskB = b.exportISK();
		expect(bytesToHex(iskA)).toBe(bytesToHex(iskB));
		// раз sid задан, sidOutput должен дублировать его
		const aSid = expectDefined(a.sidOutput, "initiator sidOutput");
		const bSid = expectDefined(b.sidOutput, "responder sidOutput");
		expect(bytesToHex(aSid)).toBe(bytesToHex(sid));
		expect(bytesToHex(bSid)).toBe(bytesToHex(sid));
	});

	it("Symmetric happy path (unordered, оба шлют/получают): ISK совпадает, и отличается от IR-режима", async () => {
		const prs = utf8("Password");
		const ci = utf8("same-ci");
		const sid = utf8("same-sid");
		const ada = utf8("ADa");
		const adb = utf8("ADb");

		const p = new CPaceSession({
			prs,
			suite,
			mode: "symmetric",
			role: "symmetric",
			ci,
			sid,
			ada: ada,
			adb: adb,
		});
		const q = new CPaceSession({
			prs,
			suite,
			mode: "symmetric",
			role: "symmetric",
			ci,
			sid,
			ada: ada,
			adb: adb,
		});

		const pm = expectDefined(await p.start(), "P start message");
		const qm = expectDefined(await q.start(), "Q start message");

		await p.receive(qm);
		await q.receive(pm);

		// во symmetric возможен второй обмен, но в нашем CPaceSession это не требуется
		const iskP = p.exportISK();
		const iskQ = q.exportISK();

		expect(bytesToHex(iskP)).toBe(bytesToHex(iskQ));
	});

	it("Работает без CI и без sid (оба пустые): sidOutput берётся из ISK[0..16), у сторон одинаковый", async () => {
		const prs = utf8("only-password");

		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			// ci/sid не указываем
		});
		const b = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			// ci/sid не указываем
		});

		const aMsg = expectDefined(await a.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await b.receive(aMsg),
			"responder handshake message",
		);
		await a.receive(bMsg);

		expect(bytesToHex(a.exportISK())).toBe(bytesToHex(b.exportISK()));
		const aSid = expectDefined(a.sidOutput, "initiator sidOutput");
		const bSid = expectDefined(b.sidOutput, "responder sidOutput");
		expect(aSid.length).toBe(bSid.length);
		expect(bytesToHex(aSid)).toBe(bytesToHex(bSid));
	});

	it("Разные PRS -> разные ISK (при прочих равных)", async () => {
		const ci = utf8("ctx");
		const sid = utf8("sess");
		const ada = utf8("ADa");
		const adb = utf8("ADb");

		const a = new CPaceSession({
			prs: utf8("secret-1"),
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ada,
		});
		const b = new CPaceSession({
			prs: utf8("secret-2"),
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			adb,
		});

		const aMsg = expectDefined(await a.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await b.receive(aMsg),
			"responder handshake message",
		);
		await a.receive(bMsg);

		expect(bytesToHex(a.exportISK())).not.toBe(bytesToHex(b.exportISK()));
	});

	it("Разные CI -> разные ISK (CI секретен, не на проводе, но входит в g)", async () => {
		const prs = utf8("Password");
		const sid = utf8("some-sid");

		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci: utf8("CI-1"),
			sid,
			ada: utf8("ADa"),
		});
		const b = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci: utf8("CI-2"),
			sid,
			adb: utf8("ADb"),
		});

		const aMsg = expectDefined(await a.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await b.receive(aMsg),
			"responder handshake message",
		);
		await a.receive(bMsg);

		expect(bytesToHex(a.exportISK())).not.toBe(bytesToHex(b.exportISK()));
	});

	it("Разные sid -> разные ISK (sid публичен, но MUST совпадать)", async () => {
		const prs = utf8("Password");
		const ci = utf8("CI");

		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid: utf8("SID-1"),
			ada: utf8("ADa"),
		});
		const b = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid: utf8("SID-2"),
			adb: utf8("ADb"),
		});

		const aMsg = expectDefined(await a.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await b.receive(aMsg),
			"responder handshake message",
		);
		await a.receive(bMsg);

		expect(bytesToHex(a.exportISK())).not.toBe(bytesToHex(b.exportISK()));
	});

	it("Изменение AD (ADa/ADb) меняет transcript и ISK", async () => {
		const prs = utf8("Password");
		const ci = utf8("CI");
		const sid = utf8("SID");

		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ada: utf8("ADa-v1"),
		});
		const b = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			adb: utf8("ADb"),
		});

		const aMsg = expectDefined(await a.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await b.receive(aMsg),
			"responder handshake message",
		);
		await a.receive(bMsg);

		const iskV1 = a.exportISK();

		// Повтор с другим ADa
		const a2 = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ada: utf8("ADa-v2"),
		});
		const b2 = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			adb: utf8("ADb"),
		});

		const a2Msg = expectDefined(
			await a2.start(),
			"initiator handshake message (variant)",
		);
		const b2Msg = expectDefined(
			await b2.receive(a2Msg),
			"responder handshake message (variant)",
		);
		await a2.receive(b2Msg);

		const iskV2 = a2.exportISK();
		expect(bytesToHex(iskV1)).not.toBe(bytesToHex(iskV2));
	});

	it("Abort на низкопорядковой/некорректной точке (peer message подменён)", async () => {
		const prs = utf8("Password");
		const ci = utf8("CI");
		// Подготовим корректный инициатор без sid, а ответ «подделаем»
		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			ada: utf8("ADa"),
		});

		const _aMsg = await a.start();

		// Подмена ответа: вместо реального Yb кидаем low-order u=0^32
		const fakeLowOrder = new Uint8Array(32); // u0 из векторов
		await expect(async () => {
			await a.receive({ type: "msg", payload: fakeLowOrder, adb: utf8("ADb") });
		}).rejects.toThrow(/invalid peer element/i);
	});

	it("Оба вида transcript (IR vs OC) действительно различаются и дают разные ISK", async () => {
		const prs = utf8("Password");
		const ci = utf8("CI");
		const sid = utf8("SID");
		const ADa = utf8("ADa");
		const ADb = utf8("ADb");

		// IR
		const A = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ada: ADa,
		});
		const B = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			adb: ADb,
		});
		const Am = expectDefined(await A.start(), "initiator handshake message");
		const Bm = expectDefined(
			await B.receive(Am),
			"responder handshake message",
		);
		await A.receive(Bm);
		const iskIR = A.exportISK();

		// Symmetric
		const P = new CPaceSession({
			prs,
			suite,
			mode: "symmetric",
			role: "symmetric",
			ci,
			sid,
			ada: ADa,
		});
		const Q = new CPaceSession({
			prs,
			suite,
			mode: "symmetric",
			role: "symmetric",
			ci,
			sid,
			adb: ADb,
		});
		const Pm = expectDefined(await P.start(), "symmetric P message");
		const Qm = expectDefined(await Q.start(), "symmetric Q message");
		await P.receive(Qm);
		await Q.receive(Pm);
		const iskOC = P.exportISK();

		expect(bytesToHex(iskIR)).not.toBe(bytesToHex(iskOC));
	});

	it("Swap ролей в IR при фиксированных скалярах даёт тот же ISK (детерминированный sanity-check)", async () => {
		// Для этого теста нам нужно переопределить sampleScalar,
		// чтобы обе стороны выбрали фиксированные ya/yb.
		const fixedYA = hex(
			"21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080",
		);
		const fixedYB = hex(
			"848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a",
		);

		// Оборачиваем группу (простой шпион над sampleScalar)
		const Group = Object.create(G_X25519);
		let calls = 0;
		Group.sampleScalar = () =>
			++calls % 2 === 1 ? fixedYA.slice() : fixedYB.slice();

		const detSuite: CPaceSuiteDesc = {
			name: suite.name,
			group: Group,
			hash: sha512,
		};

		const prs = utf8("Password");
		const ci = utf8("CI");
		const sid = utf8("SID");
		const ADa = utf8("ADa");
		const ADb = utf8("ADb");

		// Сценарий 1: A=initiator, B=responder
		const A1 = new CPaceSession({
			prs,
			suite: detSuite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ada: ADa,
		});
		const B1 = new CPaceSession({
			prs,
			suite: detSuite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			adb: ADb,
		});
		const A1m = expectDefined(await A1.start(), "A1 start message");
		const B1m = expectDefined(await B1.receive(A1m), "B1 response message");
		await A1.receive(B1m);
		const isk1 = A1.exportISK();

		// Сценарий 2: меняем роли
		const A2 = new CPaceSession({
			prs,
			suite: detSuite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			adb: ADb,
		});
		const B2 = new CPaceSession({
			prs,
			suite: detSuite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ada: ADa,
		});
		const B2m = expectDefined(await B2.start(), "B2 start message");
		const A2m = expectDefined(await A2.receive(B2m), "A2 response message");
		await B2.receive(A2m);
		const isk2 = B2.exportISK();

		expect(bytesToHex(isk1)).toBe(bytesToHex(isk2));
	});

	it("IR mode: equal ISK and equal sidOutput (no input sid)", async () => {
		const suite = {
			name: "CPACE-X25519-SHA512",
			group: G_X25519,
			hash: sha512,
		};
		const prs = utf8("only-password");

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

		const aMsg = expectDefined(await A.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await B.receive(aMsg),
			"responder handshake message",
		);
		await A.receive(bMsg);

		expect(bytesToHex(A.exportISK())).toBe(bytesToHex(B.exportISK()));
		const Asid = expectDefined(A.sidOutput, "initiator sidOutput");
		const Bsid = expectDefined(B.sidOutput, "responder sidOutput");
		expect(bytesToHex(Asid)).toBe(bytesToHex(Bsid));
	});
});
