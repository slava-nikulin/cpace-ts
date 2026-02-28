import { compareBytes } from "./bytes";
import { LowOrderPointError } from "./cpace-group-x25519";
import type { CPaceSuiteDesc } from "./cpace-session";
import { InvalidPeerElementError } from "./cpace-session";
import { concat, lvCat, utf8 } from "./cpace-strings";

const EMPTY = new Uint8Array(0);

/**
 * @internal Generate this party's CPace element and serialized message payload.
 */
export async function computeLocalElement(
	suite: CPaceSuiteDesc,
	prs: Uint8Array,
	ci?: Uint8Array,
	sid?: Uint8Array,
): Promise<{ scalar: Uint8Array; serialized: Uint8Array }> {
	const pwdPoint = await suite.group.calculateGenerator(
		suite.hash,
		prs,
		ci ?? EMPTY,
		sid ?? EMPTY,
	);
	const scalar = suite.group.sampleScalar();
	const point = await suite.group.scalarMult(scalar, pwdPoint);
	const serialized = suite.group.serialize(point);
	return { scalar, serialized };
}

/**
 * @internal Derive the shared secret from the peer's message or throw if invalid.
 * @throws InvalidPeerElementError when deserialization or scalar multiplication fails.
 */
export async function deriveSharedSecretOrThrow(
	suite: CPaceSuiteDesc,
	ephemeralScalar: Uint8Array,
	peerPayload: Uint8Array,
	onPeerInvalid: (errName: string, message?: string) => void,
	onLowOrder: () => void,
): Promise<Uint8Array> {
	let peerPoint: Uint8Array;
	try {
		peerPoint = suite.group.deserialize(peerPayload);
	} catch (err) {
		onPeerInvalid(
			err instanceof Error ? (err.name ?? "Error") : "UnknownError",
			err instanceof Error ? err.message : undefined,
		);
		throw new InvalidPeerElementError(undefined, {
			cause: err instanceof Error ? err : undefined,
		});
	}

	let sharedSecret: Uint8Array;
	try {
		sharedSecret = await suite.group.scalarMultVfy(ephemeralScalar, peerPoint);
	} catch (err) {
		if (err instanceof LowOrderPointError) {
			onLowOrder();
		} else {
			onPeerInvalid(
				err instanceof Error ? (err.name ?? "Error") : "UnknownError",
				err instanceof Error ? err.message : undefined,
			);
		}
		throw new InvalidPeerElementError(undefined, {
			cause: err instanceof Error ? err : undefined,
		});
	}

	if (compareBytes(sharedSecret, suite.group.I) === 0) {
		onLowOrder();
		throw new InvalidPeerElementError();
	}

	return sharedSecret;
}

/**
 * @internal Obtain the session key material and sid output from transcript data.
 */
export async function deriveIskAndSid(
	suite: CPaceSuiteDesc,
	transcript: Uint8Array,
	sharedSecret: Uint8Array,
	sid?: Uint8Array,
): Promise<{ isk: Uint8Array; sidOutput?: Uint8Array }> {
	const dsiIsk = concat([suite.group.DSI, utf8("_ISK")]);

	// In CPace, sid is an input string. If not present, treat as empty string.
	const sidBytes = sid ?? EMPTY;

	// ISK = H.hash(lv_cat(DSI||"_ISK", sid, K) || transcript)
	const lvPart = lvCat(dsiIsk, sidBytes, sharedSecret);
	const isk = await suite.hash(concat([lvPart, transcript]));

	// sid_output exists only for the "empty sid" run (Section 9.6)
	if (sidBytes.length === 0) {
		const sidOutput = await suite.hash(
			concat([utf8("CPaceSidOutput"), transcript]),
		);
		return { isk, sidOutput }; // full hash output (SHA-512 => 64 bytes)
	}

	return { isk };
}
