import { compareBytes } from "./bytes";
import type { AuditLevel, AuditLogger } from "./cpace-audit";
import { AUDIT_CODES, emitAuditEvent } from "./cpace-audit";
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
const EMPTY = new Uint8Array(0);
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

export interface CPaceMessage {
	type: "msg";
	payload: Uint8Array;
	ada?: Uint8Array;
	adb?: Uint8Array;
}

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
	private readonly inputs: CPaceInputs;

	private ephemeralScalar: Uint8Array | undefined;
	private localMsg: Uint8Array | undefined;
	private iskValue: Uint8Array | undefined;
	private sidValue: Uint8Array | undefined;

	/**
	 * Instantiate a CPace session for a local participant.
	 *
	 * @param options Protocol inputs and optional audit logger/session id.
	 */
	constructor(
		options: CPaceInputs & { audit?: AuditLogger; sessionId?: string },
	) {
		const { audit, sessionId, ...inputs } = options;
		this.auditLogger = audit;
		this.sessionId = sessionId ?? generateSessionId();
		this.inputs = inputs;
		if (
			(inputs.mode === "symmetric" && inputs.role !== "symmetric") ||
			(inputs.mode === "initiator-responder" && inputs.role === "symmetric")
		) {
			this.reportInputInvalid("role", "role must match selected mode", {
				mode: inputs.mode,
				role: inputs.role,
			});
			throw new Error("CPaceSession: invalid mode/role combination");
		}
		this.emitAudit(AUDIT_CODES.CPACE_SESSION_CREATED, "info", {
			mode: inputs.mode,
			role: inputs.role,
			suite: inputs.suite.name,
			ci_len: inputs.ci?.length ?? 0,
			sid_len: inputs.sid?.length ?? 0,
			ada_len: inputs.ada?.length ?? 0,
			adb_len: inputs.adb?.length ?? 0,
		});
	}

	/**
	 * Produce the local CPace message when acting as initiator or symmetric peer.
	 *
	 * @returns The outbound CPace message, or `undefined` when a responder should wait.
	 * @throws Error if required inputs are missing or invalid.
	 */
	async start(): Promise<CPaceMessage | undefined> {
		const { suite, prs, ci, sid, ada, adb, role, mode } = this.inputs;

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

		this.emitAudit(AUDIT_CODES.CPACE_START_BEGIN, "info", { mode, role });

		const pwdPoint = await suite.group.calculateGenerator(
			suite.hash,
			normalizedPrs,
			normalizedCi ?? EMPTY,
			normalizedSid ?? EMPTY,
		);
		const x = suite.group.sampleScalar();
		const X = await suite.group.scalarMult(x, pwdPoint);

		this.ephemeralScalar = x;
		this.localMsg = suite.group.serialize(X);

		if (mode === "initiator-responder" && role === "responder") {
			return undefined;
		}

		const result: CPaceMessage = {
			type: "msg",
			payload: this.localMsg,
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

		this.emitAudit(AUDIT_CODES.CPACE_START_SENT, "info", {
			payload_len: result.payload.length,
			ada_present: Boolean(result.ada && result.ada.length > 0),
			adb_present: Boolean(result.adb && result.adb.length > 0),
		});

		return result;
	}

	/**
	 * Consume a peer CPace message and, when required, return a response.
	 *
	 * @param msg Peer message containing the serialized group element and optional AD.
	 * @returns A response message for responder roles, otherwise `undefined`.
	 * @throws InvalidPeerElementError when peer inputs are malformed or low-order.
	 */
	async receive(msg: CPaceMessage): Promise<CPaceMessage | undefined> {
		const { prs, sid, adb, role, mode, suite } = this.inputs;

		this.ensureField("prs", prs, {
			optional: false,
			minLength: 1,
		});
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
			!this.localMsg
		) {
			await this.start();
		}

		const sanitizedPeerMsg: CPaceMessage = { type: "msg", payload };
		if (hasPeerAda && peerAda) sanitizedPeerMsg.ada = peerAda;
		if (hasPeerAdb && peerAdb) sanitizedPeerMsg.adb = peerAdb;

		this.emitAudit(AUDIT_CODES.CPACE_RX_RECEIVED, "info", {
			payload_len: payload.length,
			ada_present: Boolean(
				sanitizedPeerMsg.ada && sanitizedPeerMsg.ada.length > 0,
			),
			adb_present: Boolean(
				sanitizedPeerMsg.adb && sanitizedPeerMsg.adb.length > 0,
			),
		});

		this.iskValue = await this.finish(normalizedSid, sanitizedPeerMsg);

		if (mode === "initiator-responder" && role === "responder") {
			if (!this.localMsg) {
				throw new Error("CPaceSession.receive: missing outbound message");
			}
			const response: CPaceMessage = {
				type: "msg",
				payload: this.localMsg,
			};
			if (normalizedSessionAdb) {
				response.adb = normalizedSessionAdb;
			}
			this.emitAudit(AUDIT_CODES.CPACE_START_SENT, "info", {
				payload_len: response.payload.length,
				ada_present: false,
				adb_present: Boolean(response.adb && response.adb.length > 0),
			});
			return response;
		}

		return undefined;
	}

	/**
	 * Export the derived session key after `receive` completes the handshake.
	 *
	 * @returns The session's intermediate shared key (ISK).
	 * @throws Error if the session has not successfully finished.
	 */
	exportISK(): Uint8Array {
	if (!this.iskValue) throw new Error("CPaceSession: not finished");
	return this.iskValue;
	}

	/**
	 * Obtain the session identifier output negotiated during the handshake, if any.
	 */
	get sidOutput(): Uint8Array | undefined {
		return this.sidValue;
	}

	private async finish(
		sid: Uint8Array | undefined,
		peerMsg: CPaceMessage,
	): Promise<Uint8Array> {
	if (!this.ephemeralScalar || !this.localMsg) {
		throw new Error("CPaceSession.finish: session not started");
	}

	const { suite, mode, role, ada, adb } = this.inputs;
		const normalizedAda = this.ensureField("ada", ada);
		const normalizedAdb = this.ensureField("adb", adb);

		this.emitAudit(AUDIT_CODES.CPACE_FINISH_BEGIN, "info", { mode, role });

		let peerPoint: Uint8Array;
		try {
			peerPoint = suite.group.deserialize(peerMsg.payload);
		} catch (err) {
			this.emitAudit(AUDIT_CODES.CPACE_PEER_INVALID, "error", {
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
				this.emitAudit(AUDIT_CODES.CPACE_LOW_ORDER_POINT, "security", {});
			} else {
				this.emitAudit(AUDIT_CODES.CPACE_PEER_INVALID, "error", {
					error: err instanceof Error ? (err.name ?? "Error") : "UnknownError",
					message: err instanceof Error ? err.message : undefined,
				});
			}
			throw new InvalidPeerElementError(undefined, {
				cause: err instanceof Error ? err : undefined,
			});
		}

		if (compareBytes(k, suite.group.I) === 0) {
			this.emitAudit(AUDIT_CODES.CPACE_LOW_ORDER_POINT, "security", {});
			throw new InvalidPeerElementError();
		}

		let transcript: Uint8Array;
		if (mode === "initiator-responder") {
			transcript =
				role === "initiator"
			? transcriptIr(
				this.localMsg,
				normalizedAda ?? EMPTY,
				peerMsg.payload,
				peerMsg.adb ?? EMPTY,
			)
			: transcriptIr(
				peerMsg.payload,
				peerMsg.ada ?? EMPTY,
				this.localMsg,
				normalizedAdb ?? EMPTY,
			);
		} else {
			const { localAd, remoteAd } = this.selectSymmetricAssociatedData(
				mode,
				normalizedAda,
				normalizedAdb,
				peerMsg,
			);
		transcript = transcriptOc(
			this.localMsg,
			localAd,
			peerMsg.payload,
				remoteAd,
			);
		}

		const dsiIsk = concat([suite.group.DSI, utf8("_ISK")]);
		const sidBytes = sid ?? EMPTY;
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

		if (this.ephemeralScalar) {
			this.ephemeralScalar.fill(0);
			this.ephemeralScalar = undefined;
		}
		k.fill(0);

		this.emitAudit(AUDIT_CODES.CPACE_FINISH_OK, "info", {
			transcript_type: mode === "initiator-responder" ? "ir" : "oc",
			sid_provided: Boolean(sid && sid.length > 0),
		});

		return isk;
	}

	private selectSymmetricAssociatedData(
		mode: CPaceMode,
		normalizedAda: Uint8Array | undefined,
		normalizedAdb: Uint8Array | undefined,
		peerMsg: CPaceMessage,
	): { localAd: Uint8Array; remoteAd: Uint8Array } {
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
		const localAd = normalizedAda ?? normalizedAdb ?? EMPTY;
		const remoteAd = peerAdaBytes ?? peerAdbBytes ?? EMPTY;
		return { localAd, remoteAd };
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
		this.emitAudit(AUDIT_CODES.CPACE_INPUT_INVALID, "warn", {
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
