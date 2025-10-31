// test/cpace.fuzz.integration.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

function randBytes(n: number): Uint8Array {
	const out = new Uint8Array(n);
	crypto.getRandomValues(out);
	return out;
}

function randAscii(n: number): Uint8Array {
	const bytes = new Uint8Array(n);
	for (let i = 0; i < n; i++) {
		// видимые ASCII (0x20..0x7E)
		bytes[i] = (0x20 + Math.random() * 95) | 0;
	}
	return bytes;
}

function maybe<T>(x: T): T | undefined {
	return Math.random() < 0.5 ? undefined : x;
}

function mutateOneByte(x: Uint8Array): Uint8Array {
	if (x.length === 0) return new Uint8Array([1]); // если пусто — сделаем непустым
	const y = x.slice();
	const idx = (Math.random() * y.length) | 0;
	y[idx] ^= 1 + ((Math.random() * 254) | 0); // меняем байт
	return y;
}

function suite() {
	return {
		name: "X25519+SHA512",
		group: G_X25519,
		hash: sha512, // async
	};
}

async function runCpaceIR(
	prs: Uint8Array,
	ci?: Uint8Array,
	sid?: Uint8Array,
	ADa?: Uint8Array,
	ADb?: Uint8Array,
) {
	const A = new CPaceSession({
		prs,
		suite: suite(),
		mode: "initiator-responder",
		role: "initiator",
		ci,
		sid,
		ada: ADa,
	});
	const B = new CPaceSession({
		prs,
		suite: suite(),
		mode: "initiator-responder",
		role: "responder",
		ci,
		sid,
		adb: ADb,
	});

	const msgA = await A.start(); // инициатор шлёт
	const msgB = await B.receive(
		expectDefined(msgA, "initiator handshake message"),
	); // респондер отвечает
	await A.receive(expectDefined(msgB, "responder handshake message")); // инициатор заканчивает

	return { A, B };
}

async function runCpaceOC(
	prs: Uint8Array,
	ci?: Uint8Array,
	sid?: Uint8Array,
	ADa?: Uint8Array,
	ADb?: Uint8Array,
) {
	// симметричный: оба могут послать в любом порядке
	const A = new CPaceSession({
		prs,
		suite: suite(),
		mode: "symmetric",
		role: "symmetric",
		ci,
		sid,
		ada: ADa,
	});
	const B = new CPaceSession({
		prs,
		suite: suite(),
		mode: "symmetric",
		role: "symmetric",
		ci,
		sid,
		adb: ADb,
	});

	const msgA = await A.start();
	const msgB = await B.start();
	const safeMsgB = expectDefined(msgB, "symmetric responder message");
	const safeMsgA = expectDefined(msgA, "symmetric initiator message");
	await A.receive({ type: "msg", payload: safeMsgB.payload, adb: ADb });
	await B.receive({ type: "msg", payload: safeMsgA.payload, ada: ADa });

	return { A, B };
}

describe("CPace fuzzing: ISK match/mismatch", () => {
	// Важно: WebCrypto async — лучше увеличить таймаут
	const ITERS = 25; // можно поднять до 100 в CI

	it("IR mode: ISK(A) == ISK(B) для одинаковых входов", async () => {
		for (let i = 0; i < ITERS; i++) {
			const prs = randAscii(4 + ((Math.random() * 24) | 0)); // 4..28 байт
			const ci = maybe(randBytes((Math.random() * 32) | 0));
			const sid = maybe(randBytes(16)); // либо undefined, либо 16B
			const ADa = maybe(randAscii((Math.random() * 8) | 0));
			const ADb = maybe(randAscii((Math.random() * 8) | 0));

			const { A, B } = await runCpaceIR(prs, ci, sid, ADa, ADb);
			expect(A.exportISK()).toEqual(B.exportISK());
			// sidOutput policy:
			if (sid && sid.length > 0) {
				expect(A.sidOutput).toEqual(sid);
				expect(B.sidOutput).toEqual(sid);
			} else {
				expect(expectDefined(A.sidOutput, "initiator sidOutput").length).toBe(
					16,
				);
				expect(expectDefined(B.sidOutput, "responder sidOutput").length).toBe(
					16,
				);
			}
		}
	});

	it("IR mode: точечные изменения входов дают разные ISK", async () => {
		for (let i = 0; i < ITERS; i++) {
			const prs = randAscii(12);
			const ci = maybe(randBytes(10));
			const sid = maybe(randBytes(16));
			const ADa = maybe(randAscii(5));
			const ADb = maybe(randAscii(5));

			const base = await runCpaceIR(prs, ci, sid, ADa, ADb);
			const ref = base.A.exportISK();

			// PRS мутация
			{
				const { A } = await runCpaceIR(mutateOneByte(prs), ci, sid, ADa, ADb);
				expect(A.exportISK()).not.toEqual(ref);
			}
			// CI мутация
			{
				const { A } = await runCpaceIR(
					prs,
					ci ? mutateOneByte(ci) : randBytes(1),
					sid,
					ADa,
					ADb,
				);
				expect(A.exportISK()).not.toEqual(ref);
			}
			// SID мутация/удаление
			{
				const sid2 = sid ? mutateOneByte(sid) : randBytes(8);
				const { A } = await runCpaceIR(prs, ci, sid2, ADa, ADb);
				expect(A.exportISK()).not.toEqual(ref);
			}
			// ADa мутация
			{
				const { A } = await runCpaceIR(
					prs,
					ci,
					sid,
					ADa ? mutateOneByte(ADa) : randAscii(1),
					ADb,
				);
				expect(A.exportISK()).not.toEqual(ref);
			}
			// ADb мутация
			{
				const { A } = await runCpaceIR(
					prs,
					ci,
					sid,
					ADa,
					ADb ? mutateOneByte(ADb) : randAscii(1),
				);
				expect(A.exportISK()).not.toEqual(ref);
			}
		}
	});

	it("OC mode: ISK(A) == ISK(B) для одинаковых входов", async () => {
		for (let i = 0; i < ITERS; i++) {
			const prs = randAscii(6 + ((Math.random() * 24) | 0));
			const ci = maybe(randBytes((Math.random() * 32) | 0));
			const sid = maybe(randBytes(16));
			const ADa = maybe(randAscii((Math.random() * 8) | 0));
			const ADb = maybe(randAscii((Math.random() * 8) | 0));

			const { A, B } = await runCpaceOC(prs, ci, sid, ADa, ADb);
			expect(A.exportISK()).toEqual(B.exportISK());
			if (sid && sid.length > 0) {
				expect(A.sidOutput).toEqual(sid);
				expect(B.sidOutput).toEqual(sid);
			} else {
				expect(expectDefined(A.sidOutput, "symmetric sidOutput A").length).toBe(
					16,
				);
				expect(expectDefined(B.sidOutput, "symmetric sidOutput B").length).toBe(
					16,
				);
			}
		}
	});

	it("OC mode: точечные изменения входов дают разные ISK", async () => {
		for (let i = 0; i < ITERS; i++) {
			const prs = randAscii(10);
			const ci = maybe(randBytes(7));
			const sid = maybe(randBytes(16));
			const ADa = maybe(randAscii(5));
			const ADb = maybe(randAscii(5));

			const base = await runCpaceOC(prs, ci, sid, ADa, ADb);
			const ref = base.A.exportISK();

			const fields: Array<[string, Uint8Array | undefined]> = [
				["PRS", prs],
				["CI", ci],
				["SID", sid],
				["ADa", ADa],
				["ADb", ADb],
			];

			for (const [name, _val] of fields) {
				const prs2 = name === "PRS" ? mutateOneByte(prs) : prs;
				const ci2 =
					name === "CI" ? (ci ? mutateOneByte(ci) : randBytes(1)) : ci;
				const sid2 =
					name === "SID" ? (sid ? mutateOneByte(sid) : randBytes(9)) : sid;
				const ADa2 =
					name === "ADa" ? (ADa ? mutateOneByte(ADa) : randAscii(1)) : ADa;
				const ADb2 =
					name === "ADb" ? (ADb ? mutateOneByte(ADb) : randAscii(1)) : ADb;

				const { A } = await runCpaceOC(prs2, ci2, sid2, ADa2, ADb2);
				expect(A.exportISK()).not.toEqual(ref);
			}
		}
	});
});
