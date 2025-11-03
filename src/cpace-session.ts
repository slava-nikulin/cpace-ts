import type { AuditLevel, AuditLogger } from "./cpace-audit";
import { AUDIT_CODES, emitAuditEvent } from "./cpace-audit";
import { type GroupEnv } from "./cpace-group-x25519";
import {
	cleanObject,
	type EnsureBytesOptions,
	ensureField as ensureFieldValidated,
	extractExpected,
	generateSessionId,
} from "./cpace-validation";
import type { HashFn } from "./hash";
import { buildOutboundMessage, validateAndSanitizePeerMessage } from "./cpace-message";
import { makeTranscriptIR, makeTranscriptOC } from "./cpace-transcript";
import {
	computeLocalElement,
	deriveIskAndSid,
	deriveSharedSecretOrThrow,
} from "./cpace-crypto";

const EMPTY = new Uint8Array(0);

export type { AuditEvent, AuditLevel, AuditLogger } from "./cpace-audit";
export { InvalidPeerElementError } from "./cpace-errors";

/**
 * Description of the cryptographic suite used for CPace.
 */
export interface CPaceSuiteDesc {
	name: string;
	group: GroupEnv;
	hash: HashFn;
}

export type CPaceMode = "initiator-responder" | "symmetric";
export type Role = "initiator" | "responder" | "symmetric";

/**
 * All inputs required to initialize a CPace session.
 */
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

/**
 * Wire-format CPace message exchanged between peers.
 */
export interface CPaceMessage {
	type: "msg";
	payload: Uint8Array;
	ada?: Uint8Array;
	adb?: Uint8Array;
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

		const normalizedPrs = this.ensureRequired("prs", prs, {
			minLength: 1,
		});
		const normalizedCi = this.ensureOptional("ci", ci);
		const normalizedSid = this.ensureOptional("sid", sid);
		const normalizedAda = this.ensureOptional("ada", ada);
		const normalizedAdb = this.ensureOptional("adb", adb);

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

	const { scalar: ephemeralScalar, serialized: localMsg } =
		await computeLocalElement(
			suite,
			normalizedPrs,
			normalizedCi,
			normalizedSid,
		);
	this.ephemeralScalar = ephemeralScalar;
	this.localMsg = localMsg;

		if (mode === "initiator-responder" && role === "responder") {
			return undefined;
		}

	const outbound = buildOutboundMessage(
		mode,
		this.localMsg,
		normalizedAda,
		normalizedAdb,
	);

	this.emitAudit(AUDIT_CODES.CPACE_START_SENT, "info", {
		payload_len: outbound.payload.length,
		ada_present: Boolean(outbound.ada?.length),
		adb_present: Boolean(outbound.adb?.length),
	});

	return outbound;
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

		this.ensureRequired("prs", prs, {
			minLength: 1,
		});
		const normalizedSid = this.ensureOptional("sid", sid);
		const normalizedSessionAdb = this.ensureOptional("adb", adb);

		const sanitizedPeerMsg = validateAndSanitizePeerMessage(
			suite,
			msg,
			(field, value) => this.ensureOptional(field, value),
			(field, reason, extra) => this.reportInputInvalid(field, reason, extra),
		);

		await this.ensureResponderHasLocalMsg(mode, role);

	this.emitAudit(AUDIT_CODES.CPACE_RX_RECEIVED, "info", {
		payload_len: sanitizedPeerMsg.payload.length,
		ada_present: Boolean(sanitizedPeerMsg.ada?.length),
		adb_present: Boolean(sanitizedPeerMsg.adb?.length),
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
			adb_present: Boolean(response.adb?.length),
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
		return this.iskValue.slice();
	}

	/**
	 * Obtain the session identifier output negotiated during the handshake, if any.
	 */
	get sidOutput(): Uint8Array | undefined {
		return this.sidValue ? this.sidValue.slice() : undefined;
	}

	private async finish(
		sid: Uint8Array | undefined,
		peerMsg: CPaceMessage,
	): Promise<Uint8Array> {
		if (!this.ephemeralScalar || !this.localMsg) {
			throw new Error("CPaceSession.finish: session not started");
		}

		const { suite, mode, role, ada, adb } = this.inputs;
		const normalizedAda = this.ensureOptional("ada", ada);
		const normalizedAdb = this.ensureOptional("adb", adb);

		this.emitAudit(AUDIT_CODES.CPACE_FINISH_BEGIN, "info", { mode, role });

		const sharedSecret = await deriveSharedSecretOrThrow(
			suite,
			this.ephemeralScalar,
			peerMsg.payload,
			(errorName, message) => {
				this.emitAudit(AUDIT_CODES.CPACE_PEER_INVALID, "error", {
					error: errorName,
					message,
				});
			},
			() => {
				this.emitAudit(AUDIT_CODES.CPACE_LOW_ORDER_POINT, "security", {});
			},
		);

		let transcript: Uint8Array;
		if (mode === "initiator-responder") {
			transcript = makeTranscriptIR(
				role as Exclude<Role, "symmetric">,
				this.localMsg,
				normalizedAda,
				normalizedAdb,
				peerMsg.payload,
				peerMsg.ada,
				peerMsg.adb,
			);
		} else {
			const { localAd, remoteAd } = this.selectSymmetricAssociatedData(
				mode,
				normalizedAda,
				normalizedAdb,
				peerMsg,
			);
			transcript = makeTranscriptOC(
				this.localMsg,
				localAd,
				peerMsg.payload,
				remoteAd,
			);
		}

		const { isk, sidValue } = await deriveIskAndSid(
			suite,
			transcript,
			sharedSecret,
			sid,
		);
		this.sidValue = sidValue;
		this.zeroizeSecrets(sharedSecret);

		this.emitAudit(AUDIT_CODES.CPACE_FINISH_OK, "info", {
			transcript_type: mode === "initiator-responder" ? "ir" : "oc",
			sid_provided: Boolean(sid?.length),
		});

		return isk;
	}

	/** @internal */
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
		const peerAdaBytes = this.ensureOptional("peer ada", peerMsg.ada);
		const peerAdbBytes = this.ensureOptional("peer adb", peerMsg.adb);
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

	/** @internal */
	private async ensureResponderHasLocalMsg(
		mode: CPaceMode,
		role: Role,
	): Promise<void> {
		if (mode === "initiator-responder" && role === "responder" && !this.localMsg) {
			await this.start();
		}
	}

	/** @internal */
	private zeroizeSecrets(...buffers: Uint8Array[]): void {
		if (this.ephemeralScalar) {
			this.ephemeralScalar.fill(0);
			this.ephemeralScalar = undefined;
		}
		for (const buffer of buffers) {
			buffer.fill(0);
		}
	}

	private ensureRequired(
		field: string,
		value: Uint8Array | undefined,
		options?: EnsureBytesOptions,
	): Uint8Array {
		const enforcedOptions: EnsureBytesOptions = { ...options, optional: false };
		return ensureFieldValidated(field, value, enforcedOptions, (err, ctx) => {
			this.reportInputInvalid(
				field,
				err instanceof Error ? err.message : "validation failed",
				this.buildValidationAuditExtra(ctx),
			);
		});
	}

private ensureOptional(
	field: string,
	value: Uint8Array | undefined,
	options?: EnsureBytesOptions,
): Uint8Array | undefined {
	if (value === undefined) return undefined;
	return ensureFieldValidated(field, value, options, (err, ctx) => {
		this.reportInputInvalid(
			field,
			err instanceof Error ? err.message : "validation failed",
			this.buildValidationAuditExtra(ctx),
		);
	});
}

private buildValidationAuditExtra(ctx: {
	options?: EnsureBytesOptions;
	value: Uint8Array | undefined;
}): { expected?: ReturnType<typeof extractExpected>; actual: number | "undefined" | null } {
	return {
		expected: extractExpected(ctx.options),
		actual:
			ctx.value instanceof Uint8Array
				? ctx.value.length
				: ctx.value === undefined
					? "undefined"
					: null,
	};
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
