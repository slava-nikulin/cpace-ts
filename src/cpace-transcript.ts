import { transcriptIr, transcriptOc } from "./cpace-strings";

const EMPTY = new Uint8Array(0);

/**
 * @internal Construct the initiator-responder transcript in IR order.
 */
export function makeTranscriptIR(
	role: "initiator" | "responder",
	localMsg: Uint8Array,
	localAda: Uint8Array | undefined,
	localAdb: Uint8Array | undefined,
	peerPayload: Uint8Array,
	peerAda: Uint8Array | undefined,
	peerAdb: Uint8Array | undefined,
): Uint8Array {
	return role === "initiator"
		? transcriptIr(localMsg, localAda ?? EMPTY, peerPayload, peerAdb ?? EMPTY)
		: transcriptIr(peerPayload, peerAda ?? EMPTY, localMsg, localAdb ?? EMPTY);
}

/**
 * @internal Construct the symmetric-mode transcript using ordered concatenation.
 */
export function makeTranscriptOC(
	localMsg: Uint8Array,
	localAd: Uint8Array,
	peerPayload: Uint8Array,
	remoteAd: Uint8Array,
): Uint8Array {
	return transcriptOc(localMsg, localAd, peerPayload, remoteAd);
}
