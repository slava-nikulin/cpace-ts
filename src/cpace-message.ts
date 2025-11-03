import { InvalidPeerElementError } from "./cpace-errors";
import type { CPaceMessage, CPaceMode, CPaceSuiteDesc } from "./cpace-session";

export function buildOutboundMessage(
	mode: CPaceMode,
	payload: Uint8Array,
	ada?: Uint8Array,
	adb?: Uint8Array,
): CPaceMessage {
	const message: CPaceMessage = { type: "msg", payload };
	if (mode === "symmetric") {
		if (ada) message.ada = ada;
		else if (adb) message.adb = adb;
	} else if (ada) {
		message.ada = ada;
	}
	return message;
}

export function validateAndSanitizePeerMessage(
	suite: CPaceSuiteDesc,
	msg: CPaceMessage,
	ensureOptional: (field: string, value?: Uint8Array) => Uint8Array | undefined,
	onInvalid: (field: string, reason: string, extra?: Record<string, unknown>) => void,
): CPaceMessage {
	if (!(msg.payload instanceof Uint8Array)) {
		throw new InvalidPeerElementError(
			"CPaceSession.receive: peer payload must be a Uint8Array",
		);
	}
	const expectedPayloadLength = suite.group.fieldSizeBytes;
	if (msg.payload.length !== expectedPayloadLength) {
		onInvalid("peer.payload", "invalid length", {
			expected: expectedPayloadLength,
			actual: msg.payload.length,
		});
		throw new InvalidPeerElementError(
			`CPaceSession.receive: peer payload must be ${expectedPayloadLength} bytes`,
		);
	}

	if (msg.ada !== undefined && msg.adb !== undefined) {
		onInvalid(
			"peer.ada/peer.adb",
			"peer message must not include both ada and adb",
		);
		throw new Error(
			"CPaceSession.receive: peer message must not include both ada and adb",
		);
	}

	const sanitized: CPaceMessage = { type: "msg", payload: msg.payload };
	const peerAda = ensureOptional("peer ada", msg.ada);
	const peerAdb = ensureOptional("peer adb", msg.adb);
	if (msg.ada !== undefined && peerAda) sanitized.ada = peerAda;
	if (msg.adb !== undefined && peerAdb) sanitized.adb = peerAdb;
	return sanitized;
}
