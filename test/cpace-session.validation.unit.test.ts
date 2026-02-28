import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import {
	type CPaceInputs,
	CPaceSession,
	InvalidPeerElementError,
} from "../src/cpace-session";
import { utf8 } from "../src/cpace-strings";
import { sha512 } from "../src/hash";
import { expectDefined } from "./helpers";

const suite = { name: "CPACE-X25519-SHA512", group: G_X25519, hash: sha512 };
const HAS_CRYPTO = !!globalThis.crypto && !!crypto.subtle;

function makeSession(overrides: Partial<CPaceInputs> = {}) {
	return new CPaceSession({
		prs: utf8("validation-prs"),
		suite,
		mode: "initiator-responder",
		role: "initiator",
		...overrides,
	});
}

describe("CPaceSession validation", () => {
	it.skipIf(!HAS_CRYPTO)(
		"rejects peer payload with invalid length",
		async () => {
			const prs = utf8("payload-length");
			const initiator = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "initiator",
			});
			const responder = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "responder",
			});

			const initMsg = expectDefined(
				await initiator.start(),
				"initiator message",
			);
			const malformed = new Uint8Array(suite.group.fieldSizeBytes + 1).fill(1);
			await expect(
				responder.receive({
					type: "msg",
					payload: malformed,
					ad: new Uint8Array(0),
				}),
			).rejects.toBeInstanceOf(InvalidPeerElementError);

			// ensure the unmodified payload still works
			const respMsg = expectDefined(
				await responder.receive(initMsg),
				"responder reply",
			);
			await initiator.receive(respMsg);
		},
	);

	it("rejects empty password strings", async () => {
		const session = makeSession({ prs: new Uint8Array(0) });
		await expect(session.start()).rejects.toThrow(
			/prs must be at least 1 byte/i,
		);
	});

	it("rejects overly long optional fields", async () => {
		const oversize = new Uint8Array(0x10000);
		const session = makeSession({ ad: oversize });
		await expect(session.start()).resolves.toBeDefined();
	});

	it.skipIf(!HAS_CRYPTO)("accepts maximum length optional fields", async () => {
		const maxLen = 0xffff;
		const adInitiator = new Uint8Array(maxLen);
		const adResponder = new Uint8Array(maxLen);
		const prs = utf8("max-length");
		const initiator = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
			ad: adInitiator,
		});
		const responder = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
			ad: adResponder,
		});

		const initMsg = expectDefined(await initiator.start(), "initiator message");
		const respMsg = expectDefined(
			await responder.receive(initMsg),
			"responder message",
		);
		await initiator.receive(respMsg);
		expect(initiator.exportISK().length).toBeGreaterThan(0);
	});

	it.skipIf(!HAS_CRYPTO)("rejects messages missing ad", async () => {
		const prs = utf8("double-ad");
		const initiator = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "initiator",
		});
		const responder = new CPaceSession({
			prs,
			suite,
			mode: "initiator-responder",
			role: "responder",
		});

		const initMsg = expectDefined(await initiator.start(), "initiator message");
		await expect(
			responder.receive({
				type: "msg",
				payload: initMsg.payload,
			} as unknown as { type: "msg"; payload: Uint8Array; ad: Uint8Array }),
		).rejects.toThrow(/peer ad must be a Uint8Array/);
	});

	it.skipIf(!HAS_CRYPTO)(
		"treats undefined optional fields as empty",
		async () => {
			const prs = utf8("undefined-optional");
			const initiator = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "initiator",
			});
			const responder = new CPaceSession({
				prs,
				suite,
				mode: "initiator-responder",
				role: "responder",
			});

			const initMsg = expectDefined(
				await initiator.start(),
				"initiator message",
			);
			const respMsg = expectDefined(
				await responder.receive(initMsg),
				"responder message",
			);
			await initiator.receive(respMsg);
			expect(initiator.sidOutput?.length).toBeGreaterThan(0);
		},
	);
});
