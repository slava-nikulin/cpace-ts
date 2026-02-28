import { InvalidPeerElementError } from "./cpace-errors";
import type { CPaceMessage, CPaceSuiteDesc } from "./cpace-session";

/**
 * @internal Validate and normalise a received CPace message.
 * @throws InvalidPeerElementError when the payload is malformed.
 */
export function validateAndSanitizePeerMessage(
	suite: CPaceSuiteDesc,
	msg: CPaceMessage,
	ensureBytes: (field: string, value: Uint8Array) => Uint8Array,
	onInvalid: (
		field: string,
		reason: string,
		extra?: Record<string, unknown>,
	) => void,
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

	if (!(msg.ad instanceof Uint8Array)) {
		onInvalid("peer.ad", "peer ad must be a Uint8Array");
		throw new InvalidPeerElementError(
			"CPaceSession.receive: peer ad must be a Uint8Array",
		);
	}

	// Allow empty ad; normalization/validation (e.g. max length) can be done by ensureBytes
	const peerAd = ensureBytes("peer ad", msg.ad);

	return { type: "msg", payload: msg.payload, ad: peerAd };
}
