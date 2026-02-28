// test/cpace.fuzz.integration.test.ts
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { CPaceSession } from "../src/cpace-session";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

function randBytes(n: number): Uint8Array {
	const out = new Uint8Array(n);
	const cryptoObj = globalThis.crypto;
	if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") {
		throw new Error(
			"crypto.getRandomValues is unavailable in this environment",
		);
	}
	cryptoObj.getRandomValues(out);
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
	const current = y[idx] ?? 0;
	y[idx] = current ^ (1 + ((Math.random() * 254) | 0)); // меняем байт
	return y;
}

function suite() {
	return {
		name: "X25519+SHA512",
		group: G_X25519,
		hash: sha512, // async
	};
}

type SymmetricAd = Uint8Array;

function randomSymmetricAd(maxLen: number): SymmetricAd | undefined {
	if (Math.random() < 0.5) return undefined;
	return randAscii((Math.random() * maxLen) | 0);
}

async function runCpaceIR(
	prs: Uint8Array,
	ci?: Uint8Array,
	sid?: Uint8Array,
	ADa?: Uint8Array,
	ADb?: Uint8Array,
) {
	const suiteDesc = suite();
	const initiator = new CPaceSession({
		prs,
		suite: suiteDesc,
		mode: "initiator-responder",
		role: "initiator",
		...(ci !== undefined ? { ci } : {}),
		...(sid !== undefined ? { sid } : {}),
		...(ADa !== undefined ? { ad: ADa } : {}),
	});
	const responder = new CPaceSession({
		prs,
		suite: suiteDesc,
		mode: "initiator-responder",
		role: "responder",
		...(ci !== undefined ? { ci } : {}),
		...(sid !== undefined ? { sid } : {}),
		...(ADb !== undefined ? { ad: ADb } : {}),
	});

	const msgA = await initiator.start(); // инициатор шлёт
	const msgB = await responder.receive(
		expectDefined(msgA, "initiator handshake message"),
	); // респондер отвечает
	await initiator.receive(expectDefined(msgB, "responder handshake message")); // инициатор заканчивает

	return { A: initiator, B: responder };
}

async function runCpaceOC(
	prs: Uint8Array,
	ci?: Uint8Array,
	sid?: Uint8Array,
	adA?: SymmetricAd,
	adB?: SymmetricAd,
) {
	const suiteDesc = suite();
	const mkInputs = (ad?: SymmetricAd) => ({
		prs,
		suite: suiteDesc,
		mode: "symmetric" as const,
		role: "symmetric" as const,
		...(ci !== undefined ? { ci } : {}),
		...(sid !== undefined ? { sid } : {}),
		...(ad !== undefined ? { ad } : {}),
	});

	const A = new CPaceSession(mkInputs(adA));
	const B = new CPaceSession(mkInputs(adB));

	const msgA = expectDefined(await A.start(), "symmetric initiator message");
	const msgB = expectDefined(await B.start(), "symmetric responder message");
	await A.receive(msgB);
	await B.receive(msgA);

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
				expect(A.sidOutput).toEqual(undefined);
				expect(B.sidOutput).toEqual(undefined);
			} else {
				expect(expectDefined(A.sidOutput, "initiator sidOutput").length).toBe(
					64,
				);
				expect(expectDefined(B.sidOutput, "responder sidOutput").length).toBe(
					64,
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
			const adA = randomSymmetricAd(8);
			const adB = randomSymmetricAd(8);

			const { A, B } = await runCpaceOC(prs, ci, sid, adA, adB);
			expect(A.exportISK()).toEqual(B.exportISK());
			if (sid && sid.length > 0) {
				expect(A.sidOutput).toEqual(undefined);
				expect(B.sidOutput).toEqual(undefined);
			} else {
				expect(expectDefined(A.sidOutput, "symmetric sidOutput A").length).toBe(
					64,
				);
				expect(expectDefined(B.sidOutput, "symmetric sidOutput B").length).toBe(
					64,
				);
			}
		}
	});

	it("OC mode: точечные изменения входов дают разные ISK", async () => {
		for (let i = 0; i < ITERS; i++) {
			const prs = randAscii(10);
			const ci = maybe(randBytes(7));
			const sid = maybe(randBytes(16));
			const adA = randomSymmetricAd(5);
			const adB = randomSymmetricAd(5);

			const base = await runCpaceOC(prs, ci, sid, adA, adB);
			const ref = base.A.exportISK();

			{
				const { A } = await runCpaceOC(mutateOneByte(prs), ci, sid, adA, adB);
				expect(A.exportISK()).not.toEqual(ref);
			}
			{
				const { A } = await runCpaceOC(
					prs,
					ci ? mutateOneByte(ci) : randBytes(1),
					sid,
					adA,
					adB,
				);
				expect(A.exportISK()).not.toEqual(ref);
			}
			{
				const { A } = await runCpaceOC(
					prs,
					ci,
					sid ? mutateOneByte(sid) : randBytes(9),
					adA,
					adB,
				);
				expect(A.exportISK()).not.toEqual(ref);
			}
			{
				const mutatedAdA: SymmetricAd | undefined = adA
					? mutateOneByte(adA)
					: randAscii(1);
				const { A } = await runCpaceOC(prs, ci, sid, mutatedAdA, adB);
				expect(A.exportISK()).not.toEqual(ref);
			}
			{
				const mutatedAdB: SymmetricAd | undefined = adB
					? mutateOneByte(adB)
					: randAscii(1);
				const { A } = await runCpaceOC(prs, ci, sid, adA, mutatedAdB);
				expect(A.exportISK()).not.toEqual(ref);
			}
			{
				const swappedAdA: SymmetricAd | undefined =
					adA === undefined ? randAscii(1) : undefined;
				const swappedAdB: SymmetricAd | undefined =
					adB === undefined ? randAscii(1) : undefined;
				const { A } = await runCpaceOC(prs, ci, sid, swappedAdA, swappedAdB);
				expect(A.exportISK()).not.toEqual(ref);
			}
		}
	});
});
