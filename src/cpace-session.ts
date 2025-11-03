import { compareBytes } from "./bytes";
import type { AuditLevel, AuditLogger } from "./cpace-audit";
import { emitAuditEvent } from "./cpace-audit";
import {
	type GroupEnv,
	LowOrderPointError,
	type LowOrderPointReason,
} from "./cpace-group-x25519";
import {
	concat,
	lvCat,
	transcriptIr,
	transcriptOc,
	utf8,
} from "./cpace-strings";
import {
	cleanObject,
	type EnsureBytesOptions,
	ensureField as ensureFieldValidated,
	extractExpected,
	generateSessionId,
} from "./cpace-validation";
import type { HashFn } from "./hash";

export type { AuditEvent, AuditLevel, AuditLogger } from "./cpace-audit";

export interface CPaceSuiteDesc {
	name: string;
	group: GroupEnv;
	hash: HashFn;
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
	private readonly auditLogger: AuditLogger | undefined;
	private readonly sessionId: string;
	private readonly inps: CPaceInputs;

	private ephemeralScalar?: Uint8Array;
	private ourMsg?: Uint8Array;
	private isk?: Uint8Array;
	private sidValue?: Uint8Array;

	constructor(
		options: CPaceInputs & { audit?: AuditLogger; sessionId?: string },
	) {
		const { audit, sessionId, ...inps } = options;
		this.auditLogger = audit;
		this.sessionId = sessionId ?? generateSessionId();
		this.inps = inps;
		this.emitAudit("CPACE_SESSION_CREATED", "info", {
			mode: inps.mode,
			role: inps.role,
			suite: inps.suite.name,
			ci_len: inps.ci?.length ?? 0,
			sid_len: inps.sid?.length ?? 0,
			ada_len: inps.ada?.length ?? 0,
			adb_len: inps.adb?.length ?? 0,
		});
	}

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

		const normalizedPrs = this.ensureField("prs", prs, {
			optional: false,
			minLength: 1,
		});
		const normalizedCi = this.ensureField("ci", ci);
		const normalizedSid = this.ensureField("sid", sid);
		const normalizedAda = this.ensureField("ada", ada);
		const normalizedAdb = this.ensureField("adb", adb);

		if (mode === "symmetric" && normalizedAda && normalizedAdb) {
			this.reportInputInvalid(
				"ada/adb",
				"symmetric mode accepts either ada or adb",
				{
					mode,
				},
			);
			throw new Error(
				"CPaceSession.start: symmetric mode accepts either ada or adb, not both",
			);
		}

		this.emitAudit("CPACE_START_BEGIN", "info", { mode, role });

		const pwdPoint = await suite.group.calculateGenerator(
			suite.hash,
			normalizedPrs,
			normalizedCi ?? new Uint8Array(0),
			normalizedSid ?? new Uint8Array(0),
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

		this.emitAudit("CPACE_START_SENT", "info", {
			payload_len: result.payload.length,
			ada_present: Boolean(result.ada && result.ada.length > 0),
			adb_present: Boolean(result.adb && result.adb.length > 0),
		});

		return result;
	}

	async receive(msg: {
		type: "msg";
		payload: Uint8Array;
		ada?: Uint8Array;
		adb?: Uint8Array;
	}): Promise<
		{ type: "msg"; payload: Uint8Array; adb?: Uint8Array } | undefined
	> {
		const { prs, ci, sid, adb, role, mode, suite } = this.inps;

		this.ensureField("prs", prs, {
			optional: false,
			minLength: 1,
		});
		this.ensureField("ci", ci);
		const normalizedSid = this.ensureField("sid", sid);
		const normalizedSessionAdb = this.ensureField("adb", adb);

		if (!(msg.payload instanceof Uint8Array)) {
			throw new InvalidPeerElementError(
				"CPaceSession.receive: peer payload must be a Uint8Array",
			);
		}
		const expectedPayloadLength = suite.group.fieldSizeBytes;
		if (msg.payload.length !== expectedPayloadLength) {
			this.reportInputInvalid("peer.payload", "invalid length", {
				expected: expectedPayloadLength,
				actual: msg.payload.length,
			});
			throw new InvalidPeerElementError(
				`CPaceSession.receive: peer payload must be ${expectedPayloadLength} bytes`,
			);
		}
		const payload = msg.payload;

		if (msg.ada !== undefined && msg.adb !== undefined) {
			this.reportInputInvalid(
				"peer.ada/peer.adb",
				"peer message must not include both ada and adb",
			);
			throw new Error(
				"CPaceSession.receive: peer message must not include both ada and adb",
			);
		}
		const hasPeerAda = msg.ada !== undefined;
		const hasPeerAdb = msg.adb !== undefined;
		const peerAda = this.ensureField("peer ada", msg.ada);
		const peerAdb = this.ensureField("peer adb", msg.adb);

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

		this.emitAudit("CPACE_RX_RECEIVED", "info", {
			payload_len: payload.length,
			ada_present: Boolean(
				sanitizedPeerMsg.ada && sanitizedPeerMsg.ada.length > 0,
			),
			adb_present: Boolean(
				sanitizedPeerMsg.adb && sanitizedPeerMsg.adb.length > 0,
			),
		});

		this.isk = await this.finish(normalizedSid, sanitizedPeerMsg);

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
			this.emitAudit("CPACE_START_SENT", "info", {
				payload_len: response.payload.length,
				ada_present: false,
				adb_present: Boolean(response.adb && response.adb.length > 0),
			});
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

	private async finish(
		sid: Uint8Array | undefined,
		peerMsg: { payload: Uint8Array; ada?: Uint8Array; adb?: Uint8Array },
	): Promise<Uint8Array> {
		if (!this.ephemeralScalar || !this.ourMsg) {
			throw new Error("CPaceSession.finish: session not started");
		}

		const { suite, mode, role, ada, adb } = this.inps;
		const normalizedAda = this.ensureField("ada", ada);
		const normalizedAdb = this.ensureField("adb", adb);

		this.emitAudit("CPACE_FINISH_BEGIN", "info", { mode, role });

		let peerPoint: Uint8Array;
		try {
			peerPoint = suite.group.deserialize(peerMsg.payload);
		} catch (err) {
			this.emitAudit("CPACE_PEER_INVALID", "error", {
				error: err instanceof Error ? (err.name ?? "Error") : "UnknownError",
				message: err instanceof Error ? err.message : undefined,
			});
			throw new InvalidPeerElementError(undefined, {
				cause: err instanceof Error ? err : undefined,
			});
		}

		let k: Uint8Array;
		try {
			k = await suite.group.scalarMultVfy(this.ephemeralScalar, peerPoint);
		} catch (err) {
			if (isLowOrderError(err, "low-order")) {
				this.emitAudit("CPACE_LOW_ORDER_POINT", "security", {});
			} else {
				this.emitAudit("CPACE_PEER_INVALID", "error", {
					error: err instanceof Error ? (err.name ?? "Error") : "UnknownError",
					message: err instanceof Error ? err.message : undefined,
				});
			}
			throw new InvalidPeerElementError(undefined, {
				cause: err instanceof Error ? err : undefined,
			});
		}

		if (compareBytes(k, suite.group.I) === 0) {
			this.emitAudit("CPACE_LOW_ORDER_POINT", "security", {});
			throw new InvalidPeerElementError();
		}

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
			if (normalizedAda && normalizedAdb) {
				this.reportInputInvalid(
					"ada/adb",
					"symmetric mode expects a single associated data source",
					{ mode },
				);
				throw new Error(
					"CPaceSession.finish: symmetric mode expects a single associated data source",
				);
			}
			const peerAdaBytes = this.ensureField("peer ada", peerMsg.ada);
			const peerAdbBytes = this.ensureField("peer adb", peerMsg.adb);
			if (peerAdaBytes && peerAdbBytes) {
				this.reportInputInvalid(
					"peer.ada/peer.adb",
					"peer message must not include both ada and adb",
				);
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

		const dsiIsk = concat([suite.group.DSI, utf8("_ISK")]);
		const sidBytes = sid ?? new Uint8Array(0);
		const lvPart = lvCat(dsiIsk, sidBytes, k);
		const keyMaterial = concat([lvPart, transcript]);
		const isk = await suite.hash(keyMaterial);

		if (sid && sid.length > 0) {
			this.sidValue = sid.slice();
		} else {
			const sidOutFull = await suite.hash(
				concat([utf8("CPaceSidOutput"), transcript]),
			);
			this.sidValue = sidOutFull.slice(0, 16);
		}

		this.emitAudit("CPACE_FINISH_OK", "info", {
			transcript_type: mode === "initiator-responder" ? "ir" : "oc",
			sid_provided: Boolean(sid && sid.length > 0),
		});

		return isk;
	}

	private ensureField(
		field: string,
		value: Uint8Array | undefined,
	): Uint8Array | undefined;
	private ensureField(
		field: string,
		value: Uint8Array | undefined,
		options: EnsureBytesOptions & { optional: false },
	): Uint8Array;
	private ensureField(
		field: string,
		value: Uint8Array | undefined,
		options?: EnsureBytesOptions,
	): Uint8Array | undefined {
		if (value === undefined) {
			if (options?.optional === false) {
				return ensureFieldValidated(field, value, options, (err, ctx) => {
					this.reportInputInvalid(
						field,
						err instanceof Error ? err.message : "validation failed",
						{
							expected: extractExpected(ctx.options),
							actual: "undefined",
						},
					);
				});
			}
			return undefined;
		}
		return ensureFieldValidated(field, value, options, (err, ctx) => {
			this.reportInputInvalid(
				field,
				err instanceof Error ? err.message : "validation failed",
				{
					expected: extractExpected(ctx.options),
					actual:
						ctx.value instanceof Uint8Array
							? ctx.value.length
							: ctx.value === undefined
								? "undefined"
								: null,
				},
			);
		});
	}

	private reportInputInvalid(
		field: string,
		reason: string,
		extra?: Record<string, unknown>,
	): void {
		const extras = cleanObject(extra);
		this.emitAudit("CPACE_INPUT_INVALID", "warn", {
			field,
			reason,
			...(extras ?? {}),
		});
	}

	private emitAudit(
		code: string,
		level: AuditLevel,
		data?: Record<string, unknown>,
	): void {
		emitAuditEvent(this.auditLogger, this.sessionId, code, level, data);
	}
}

function isLowOrderError(
	err: unknown,
	reason: LowOrderPointReason,
): err is LowOrderPointError {
	return err instanceof LowOrderPointError && err.reason === reason;
}
