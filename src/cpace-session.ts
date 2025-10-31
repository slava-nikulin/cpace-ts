import { compareBytes } from "./bytes";
import { LowOrderPointError, type GroupEnv } from "./cpace-group-x25519"; // или твой путь
import {
	concat,
	lvCat,
	transcriptIr,
	transcriptOc,
	utf8,
} from "./cpace-strings";
import type { HashFn } from "./hash";

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

export class CPaceSession {
	private ephemeralScalar?: Uint8Array;
	private ourMsg?: Uint8Array;
	private isk?: Uint8Array;
	private sidValue?: Uint8Array;

	constructor(private readonly inps: CPaceInputs) {}

	// Было sync → стало async
	async start(): Promise<
		{ type: "msg"; payload: Uint8Array; ada?: Uint8Array } | undefined
	> {
		const { suite, prs, ci, sid, ada, role, mode } = this.inps;

		const pwdPoint = await suite.group.calculateGenerator(
			suite.hash,
			prs,
			ci,
			sid,
		);
		const x = suite.group.sampleScalar();
		const X = await suite.group.scalarMult(x, pwdPoint);

		this.ephemeralScalar = x;
		this.ourMsg = suite.group.serialize(X);

		if (mode === "initiator-responder" && role === "responder") {
			return undefined;
		}

		const result: { type: "msg"; payload: Uint8Array; ada?: Uint8Array } = {
			type: "msg",
			payload: this.ourMsg,
		};
		if (ada) result.ada = ada;
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
		const { prs, ci, sid, adb, role, mode } = this.inps;

		if (
			mode === "initiator-responder" &&
			role === "responder" &&
			!this.ourMsg
		) {
			await this.start();
		}

		this.isk = await this.finish(prs, ci, sid, msg);

		if (mode === "initiator-responder" && role === "responder") {
			if (!this.ourMsg) {
				throw new Error("CPaceSession.receive: missing outbound message");
			}
			const response: { type: "msg"; payload: Uint8Array; adb?: Uint8Array } = {
				type: "msg",
				payload: this.ourMsg,
			};
			if (adb) response.adb = adb;
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

		const peerPoint = suite.group.deserialize(peerMsg.payload);
		let k: Uint8Array;
		try {
			k = await suite.group.scalarMultVfy(this.ephemeralScalar, peerPoint);
		} catch (err) {
			if (err instanceof LowOrderPointError) {
				throw new Error("CPaceSession.finish: invalid peer element (G.I)");
			}
			throw err;
		}

		if (compareBytes(k, suite.group.I) === 0) {
			throw new Error("CPaceSession.finish: invalid peer element (G.I)");
		}

		// transcript
		let transcript: Uint8Array;
		if (mode === "initiator-responder") {
			transcript =
				role === "initiator"
					? transcriptIr(
							this.ourMsg,
							ada ?? new Uint8Array(0),
							peerMsg.payload,
							peerMsg.adb ?? new Uint8Array(0),
						)
					: transcriptIr(
							peerMsg.payload,
							peerMsg.ada ?? new Uint8Array(0),
							this.ourMsg,
							adb ?? new Uint8Array(0),
						);
		} else {
			transcript = transcriptOc(
				this.ourMsg,
				ada ?? new Uint8Array(0),
				peerMsg.payload,
				peerMsg.ada ?? new Uint8Array(0),
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
