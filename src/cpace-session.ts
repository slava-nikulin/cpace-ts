import { compareBytes } from "./bytes";
import type { GroupEnv } from "./cpace-group-x25519"; // или твой путь
import {
	concat,
	lvCat,
	transcriptIr,
	transcriptOc,
	utf8,
} from "./cpace-strings";
import type { HashFn } from "./hash";

const MAX_INPUT_LENGTH = 0xffff;

function ensureBytes(
	name: string,
	value: Uint8Array | undefined,
	{
		optional = true,
		minLength = 0,
		maxLength = MAX_INPUT_LENGTH,
	}: { optional?: boolean; minLength?: number; maxLength?: number } = {},
): Uint8Array {
	if (value === undefined) {
		if (!optional) {
			throw new Error(`CPaceSession: ${name} is required`);
		}
		return new Uint8Array(0);
	}
	if (!(value instanceof Uint8Array)) {
		throw new TypeError(`CPaceSession: ${name} must be a Uint8Array`);
	}
	if (value.length < minLength) {
		throw new Error(
			`CPaceSession: ${name} must be at least ${minLength} bytes`,
		);
	}
	if (value.length > maxLength) {
		throw new Error(`CPaceSession: ${name} must be at most ${maxLength} bytes`);
	}
	return value;
}

export interface CPaceSuiteDesc {
	name: string;
	group: GroupEnv;
	hash: HashFn; // теперь async
}

export type CPaceMode = "initiator-responder" | "symmetric";
export type Role = "initiator" | "responder" | "symmetric";

export type CPaceInputs = {
	prs: Uint8Array;
	suite: CPaceSuiteDesc;
	mode: CPaceMode;
	role: Role;
	ci?: Uint8Array;
	ada?: Uint8Array;
	adb?: Uint8Array;
	sid?: Uint8Array;
};

export class InvalidPeerElementError extends Error {
	constructor(
		message = "CPaceSession.finish: invalid peer element",
		options?: ErrorOptions,
	) {
		super(message, options);
		this.name = "InvalidPeerElementError";
	}
}

export class CPaceSession {
	private ephemeralScalar?: Uint8Array;
	private ourMsg?: Uint8Array;
	private isk?: Uint8Array;
	private sidValue?: Uint8Array;

	constructor(private readonly inps: CPaceInputs) {}

	// Было sync → стало async
	async start(): Promise<
		| {
				type: "msg";
				payload: Uint8Array;
				ada?: Uint8Array;
				adb?: Uint8Array;
		  }
		| undefined
	> {
		const { suite, prs, ci, sid, ada, adb, role, mode } = this.inps;

		const normalizedPrs = ensureBytes("prs", prs, {
			optional: false,
			minLength: 1,
		});
		const normalizedCi = ci !== undefined ? ensureBytes("ci", ci) : undefined;
		const normalizedSid =
			sid !== undefined ? ensureBytes("sid", sid) : undefined;
		const normalizedAda =
			ada !== undefined ? ensureBytes("ada", ada) : undefined;
		const normalizedAdb =
			adb !== undefined ? ensureBytes("adb", adb) : undefined;

		if (mode === "symmetric" && normalizedAda && normalizedAdb) {
			throw new Error(
				"CPaceSession.start: symmetric mode accepts either ada or adb, not both",
			);
		}

		const pwdPoint = await suite.group.calculateGenerator(
			suite.hash,
			normalizedPrs,
			normalizedCi,
			normalizedSid,
		);
		const x = suite.group.sampleScalar();
		const X = await suite.group.scalarMult(x, pwdPoint);

		this.ephemeralScalar = x;
		this.ourMsg = suite.group.serialize(X);

		if (mode === "initiator-responder" && role === "responder") {
			return undefined;
		}

		const result: {
			type: "msg";
			payload: Uint8Array;
			ada?: Uint8Array;
			adb?: Uint8Array;
		} = {
			type: "msg",
			payload: this.ourMsg,
		};
		if (mode === "symmetric") {
			if (normalizedAda) {
				result.ada = normalizedAda;
			} else if (normalizedAdb) {
				result.adb = normalizedAdb;
			}
		} else if (normalizedAda) {
			result.ada = normalizedAda;
		}
		return result;
	}

	// Было sync → стало async
	async receive(msg: {
		type: "msg";
		payload: Uint8Array;
		ada?: Uint8Array;
		adb?: Uint8Array;
	}): Promise<
		{ type: "msg"; payload: Uint8Array; adb?: Uint8Array } | undefined
	> {
		const { prs, ci, sid, adb, role, mode, suite } = this.inps;

		const normalizedPrs = ensureBytes("prs", prs, {
			optional: false,
			minLength: 1,
		});
		const normalizedCi = ci !== undefined ? ensureBytes("ci", ci) : undefined;
		const normalizedSid =
			sid !== undefined ? ensureBytes("sid", sid) : undefined;
		const normalizedSessionAdb =
			adb !== undefined ? ensureBytes("adb", adb) : undefined;

		if (!(msg.payload instanceof Uint8Array)) {
			throw new InvalidPeerElementError(
				"CPaceSession.receive: peer payload must be a Uint8Array",
			);
		}
		const expectedPayloadLength = suite.group.fieldSizeBytes;
		if (msg.payload.length !== expectedPayloadLength) {
			throw new InvalidPeerElementError(
				`CPaceSession.receive: peer payload must be ${expectedPayloadLength} bytes`,
			);
		}
		const payload = msg.payload;

		if (msg.ada !== undefined && msg.adb !== undefined) {
			throw new Error(
				"CPaceSession.receive: peer message must not include both ada and adb",
			);
		}
		const hasPeerAda = msg.ada !== undefined;
		const hasPeerAdb = msg.adb !== undefined;
		const peerAda = hasPeerAda ? ensureBytes("peer ada", msg.ada) : undefined;
		const peerAdb = hasPeerAdb ? ensureBytes("peer adb", msg.adb) : undefined;

		if (
			mode === "initiator-responder" &&
			role === "responder" &&
			!this.ourMsg
		) {
			await this.start();
		}

		const sanitizedPeerMsg: {
			payload: Uint8Array;
			ada?: Uint8Array;
			adb?: Uint8Array;
		} = { payload };
		if (hasPeerAda && peerAda) sanitizedPeerMsg.ada = peerAda;
		if (hasPeerAdb && peerAdb) sanitizedPeerMsg.adb = peerAdb;
		this.isk = await this.finish(
			normalizedPrs,
			normalizedCi,
			normalizedSid,
			sanitizedPeerMsg,
		);

		if (mode === "initiator-responder" && role === "responder") {
			if (!this.ourMsg) {
				throw new Error("CPaceSession.receive: missing outbound message");
			}
			const response: { type: "msg"; payload: Uint8Array; adb?: Uint8Array } = {
				type: "msg",
				payload: this.ourMsg,
			};
			if (normalizedSessionAdb) {
				response.adb = normalizedSessionAdb;
			}
			return response;
		}

		return undefined;
	}

	exportISK(): Uint8Array {
		if (!this.isk) throw new Error("CPaceSession: not finished");
		return this.isk;
	}

	get sidOutput(): Uint8Array | undefined {
		return this.sidValue;
	}

	// Было sync → стало async
	private async finish(
		_prs: Uint8Array,
		_ci: Uint8Array | undefined,
		sid: Uint8Array | undefined,
		peerMsg: { payload: Uint8Array; ada?: Uint8Array; adb?: Uint8Array },
	): Promise<Uint8Array> {
		if (!this.ephemeralScalar || !this.ourMsg) {
			throw new Error("CPaceSession.finish: session not started");
		}

		const { suite, mode, role, ada, adb } = this.inps;
		const normalizedAda =
			ada !== undefined ? ensureBytes("ada", ada) : undefined;
		const normalizedAdb =
			adb !== undefined ? ensureBytes("adb", adb) : undefined;

		const peerPoint = suite.group.deserialize(peerMsg.payload);
		let k: Uint8Array;
		try {
			k = await suite.group.scalarMultVfy(this.ephemeralScalar, peerPoint);
		} catch (err) {
			throw new InvalidPeerElementError(undefined, { cause: err });
		}

		if (compareBytes(k, suite.group.I) === 0) {
			throw new InvalidPeerElementError();
		}

		// transcript
		let transcript: Uint8Array;
		if (mode === "initiator-responder") {
			transcript =
				role === "initiator"
					? transcriptIr(
							this.ourMsg,
							normalizedAda ?? new Uint8Array(0),
							peerMsg.payload,
							peerMsg.adb ?? new Uint8Array(0),
						)
					: transcriptIr(
							peerMsg.payload,
							peerMsg.ada ?? new Uint8Array(0),
							this.ourMsg,
							normalizedAdb ?? new Uint8Array(0),
						);
		} else {
			// симметричный режим: объединяем обе строки AD
			if (normalizedAda && normalizedAdb) {
				throw new Error(
					"CPaceSession.finish: symmetric mode expects a single associated data source",
				);
			}
			const hasPeerAda = peerMsg.ada !== undefined;
			const hasPeerAdb = peerMsg.adb !== undefined;
			const peerAdaBytes = hasPeerAda
				? ensureBytes("peer ada", peerMsg.ada)
				: undefined;
			const peerAdbBytes = hasPeerAdb
				? ensureBytes("peer adb", peerMsg.adb)
				: undefined;
			if (peerAdaBytes && peerAdbBytes) {
				throw new Error(
					"CPaceSession.finish: peer message must not include both ada and adb",
				);
			}
			const localAd = normalizedAda ?? normalizedAdb ?? new Uint8Array(0);
			const remoteAd = peerAdaBytes ?? peerAdbBytes ?? new Uint8Array(0);

			transcript = transcriptOc(
				this.ourMsg,
				localAd,
				peerMsg.payload,
				remoteAd,
			);
		}

		// ISK = H( lv_cat(G.DSI||"_ISK", sid, K) || transcript )
		const dsiIsk = concat([suite.group.DSI, utf8("_ISK")]);
		const sidBytes = sid ?? new Uint8Array(0);
		const lvPart = lvCat(dsiIsk, sidBytes, k);
		const keyMaterial = concat([lvPart, transcript]);
		const isk = await suite.hash(keyMaterial);

		// sidOutput:
		// - если sid задан (не пуст): просто публикуем sid как есть
		// - иначе: публикуем первые 16 байт H("CPaceSidOutput" || transcript)
		if (sid && sid.length > 0) {
			this.sidValue = sid.slice();
		} else {
			const sidOutFull = await suite.hash(
				concat([utf8("CPaceSidOutput"), transcript]),
			);
			this.sidValue = sidOutFull.slice(0, 16);
		}

		return isk;
	}
}
