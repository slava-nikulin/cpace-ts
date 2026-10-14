import { bytesToHex } from "@noble/curves/utils.js";
import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import type { CPaceSuiteDesc } from "../src/cpace-session";
import { CPaceSession } from "../src/cpace-session";
import { utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

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
	it("IR mode: peers derive matching ISKs and omit sidOutput when sid is supplied", async () => {
		const prs = utf8("Password");
		const ci = utf8("oc\u000bB_responder\u000bA_initiator");
		const sid = hex("7e4b4791d6a8ef019b936c79fb7f2c57");

		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ad: utf8("ADa"),
		});
		const b = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			ad: utf8("ADb"),
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
		expect(a.sidOutput).toBe(undefined);
		expect(b.sidOutput).toBe(undefined);
	});

	it("Symmetric mode: peers derive matching ISKs after exchanging messages", async () => {
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
			ad: ada,
		});
		const q = new CPaceSession({
			prs,
			suite,
			mode: "symmetric",
			role: "symmetric",
			ci,
			sid,
			ad: adb,
		});

		const pm = expectDefined(await p.start(), "P start message");
		const qm = expectDefined(await q.start(), "Q start message");

		await p.receive(qm);
		await q.receive(pm);

		const iskP = p.exportISK();
		const iskQ = q.exportISK();

		expect(bytesToHex(iskP)).toBe(bytesToHex(iskQ));
	});

	it("IR mode: peers derive matching ISKs and sid outputs without CI or sid", async () => {
		const prs = utf8("only-password");

		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
		});
		const b = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
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

	it("IR mode: peers derive different ISKs when PRS values differ", async () => {
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
			ad: ada,
		});
		const b = new CPaceSession({
			prs: utf8("secret-2"),
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			ad: adb,
		});

		const aMsg = expectDefined(await a.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await b.receive(aMsg),
			"responder handshake message",
		);
		await a.receive(bMsg);

		expect(bytesToHex(a.exportISK())).not.toBe(bytesToHex(b.exportISK()));
	});

	it("IR mode: peers derive different ISKs when CI values differ", async () => {
		const prs = utf8("Password");
		const sid = utf8("some-sid");

		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci: utf8("CI-1"),
			sid,
			ad: utf8("ADa"),
		});
		const b = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci: utf8("CI-2"),
			sid,
			ad: utf8("ADb"),
		});

		const aMsg = expectDefined(await a.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await b.receive(aMsg),
			"responder handshake message",
		);
		await a.receive(bMsg);

		expect(bytesToHex(a.exportISK())).not.toBe(bytesToHex(b.exportISK()));
	});

	it("IR mode: peers derive different ISKs when sid values differ", async () => {
		const prs = utf8("Password");
		const ci = utf8("CI");

		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid: utf8("SID-1"),
			ad: utf8("ADa"),
		});
		const b = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid: utf8("SID-2"),
			ad: utf8("ADb"),
		});

		const aMsg = expectDefined(await a.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await b.receive(aMsg),
			"responder handshake message",
		);
		await a.receive(bMsg);

		expect(bytesToHex(a.exportISK())).not.toBe(bytesToHex(b.exportISK()));
	});

	it("IR handshakes with different ADa produce different ISKs", async () => {
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
			ad: utf8("ADa-v1"),
		});
		const b = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			ad: utf8("ADb"),
		});

		const aMsg = expectDefined(await a.start(), "initiator handshake message");
		const bMsg = expectDefined(
			await b.receive(aMsg),
			"responder handshake message",
		);
		await a.receive(bMsg);

		const iskV1 = a.exportISK();

		const a2 = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ad: utf8("ADa-v2"),
		});
		const b2 = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			ad: utf8("ADb"),
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

	it("rejects a peer message containing the low-order u-coordinate zero", async () => {
		const prs = utf8("Password");
		const ci = utf8("CI");
		const a = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			ad: utf8("ADa"),
		});

		await a.start();

		const fakeLowOrder = new Uint8Array(32);
		await expect(async () => {
			await a.receive({ type: "msg", payload: fakeLowOrder, ad: utf8("ADb") });
		}).rejects.toThrow(/invalid peer element/i);
	});

	it("IR and symmetric handshakes produce different ISKs", async () => {
		const prs = utf8("Password");
		const ci = utf8("CI");
		const sid = utf8("SID");
		const ADa = utf8("ADa");
		const ADb = utf8("ADb");

		const A = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ad: ADa,
		});
		const B = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			ad: ADb,
		});
		const Am = expectDefined(await A.start(), "initiator handshake message");
		const Bm = expectDefined(
			await B.receive(Am),
			"responder handshake message",
		);
		await A.receive(Bm);
		const iskIR = A.exportISK();

		const P = new CPaceSession({
			prs,
			suite,
			mode: "symmetric",
			role: "symmetric",
			ci,
			sid,
			ad: ADa,
		});
		const Q = new CPaceSession({
			prs,
			suite,
			mode: "symmetric",
			role: "symmetric",
			ci,
			sid,
			ad: ADb,
		});
		const Pm = expectDefined(await P.start(), "symmetric P message");
		const Qm = expectDefined(await Q.start(), "symmetric Q message");
		await P.receive(Qm);
		await Q.receive(Pm);
		const iskOC = P.exportISK();

		expect(bytesToHex(iskIR)).not.toBe(bytesToHex(iskOC));
	});

	it("derives identical IR ISKs for equivalent handshakes with fixed scalars", async () => {
		const fixedYA = hex(
			"21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b319097153044080",
		);
		const fixedYB = hex(
			"848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19c51ac40a",
		);

		const Group = Object.create(G_X25519);
		let calls = 0;
		// Return copies because CPaceSession clears ephemeral scalars after derivation.
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

		const A1 = new CPaceSession({
			prs,
			suite: detSuite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ad: ADa,
		});
		const B1 = new CPaceSession({
			prs,
			suite: detSuite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			ad: ADb,
		});
		const A1m = expectDefined(await A1.start(), "A1 start message");
		const B1m = expectDefined(await B1.receive(A1m), "B1 response message");
		await A1.receive(B1m);
		const isk1 = A1.exportISK();

		const A2 = new CPaceSession({
			prs,
			suite: detSuite,
			mode: "initiator-responder",
			role: "responder",
			ci,
			sid,
			ad: ADb,
		});
		const B2 = new CPaceSession({
			prs,
			suite: detSuite,
			mode: "initiator-responder",
			role: "initiator",
			ci,
			sid,
			ad: ADa,
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
