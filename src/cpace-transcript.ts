import { transcriptIr, transcriptOc } from "./cpace-strings";

/**
 * @internal Construct the initiator-responder transcript in IR order.
 *
 * The message on the wire is (Y, AD) where AD belongs to the sender.
 * In IR mode, AD is named ADa for the initiator and ADb for the responder.
 */
export function makeTranscriptIR(
	role: "initiator" | "responder",
	localMsg: Uint8Array,
	localAd: Uint8Array,
	peerPayload: Uint8Array,
	peerAd: Uint8Array,
): Uint8Array {
	return role === "initiator"
		? transcriptIr(localMsg, localAd, peerPayload, peerAd)
		: transcriptIr(peerPayload, peerAd, localMsg, localAd);
}

/**
 * @internal Construct the symmetric-mode transcript using ordered concatenation.
 */
export function makeTranscriptOC(
	localMsg: Uint8Array,
	localAd: Uint8Array,
	peerPayload: Uint8Array,
	peerAd: Uint8Array,
): Uint8Array {
	return transcriptOc(localMsg, localAd, peerPayload, peerAd);
}
