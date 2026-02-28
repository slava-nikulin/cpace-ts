import type { AuditLevel, AuditLogger } from "./cpace-audit";
import { AUDIT_CODES, emitAuditEvent } from "./cpace-audit";
import {
	computeLocalElement,
	deriveIskAndSid,
	deriveSharedSecretOrThrow,
} from "./cpace-crypto";
import type { GroupEnv } from "./cpace-group-x25519";
import { validateAndSanitizePeerMessage } from "./cpace-message";
import { makeTranscriptIR, makeTranscriptOC } from "./cpace-transcript";
import {
	cleanObject,
	type EnsureBytesOptions,
	ensureField as ensureFieldValidated,
	extractExpected,
	generateSessionId,
} from "./cpace-validation";
import type { HashFn } from "./hash";

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
export type CPaceRole = "initiator" | "responder" | "symmetric";

/**
 * All inputs required to initialize a CPace session.
 */
export type CPaceInputs = {
	prs: Uint8Array;
	suite: CPaceSuiteDesc;
	mode: CPaceMode;
	role: CPaceRole;
	ad?: Uint8Array;
	ci?: Uint8Array;
	sid?: Uint8Array;
};

/**
 * Wire-format CPace message exchanged between peers.
 */
export type CPaceMessage = { type: "msg"; payload: Uint8Array; ad: Uint8Array };

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

		// normalize ad once
		this.inputs = {
			...inputs,
			ad: inputs.ad ?? EMPTY,
			ci: inputs.ci ?? EMPTY,
			sid: inputs.sid ?? EMPTY,
		};

		const { mode, role, suite, ci, sid, ad } = this.inputs;

		if (
			(mode === "symmetric" && role !== "symmetric") ||
			(mode === "initiator-responder" && role === "symmetric")
		) {
			this.reportInputInvalid("role", "role must match selected mode", {
				mode,
				role,
			});
			throw new Error("CPaceSession: invalid mode/role combination");
		}

		this.emitAudit(AUDIT_CODES.CPACE_SESSION_CREATED, "info", {
			mode,
			role,
			suite: suite.name,
			ci_len: ci?.length ?? 0,
			sid_len: sid?.length ?? 0,
			ad_len: ad?.length,
		});
	}

	/**
	 * Produce the local CPace message when acting as initiator or symmetric peer.
	 *
	 * @returns The outbound CPace message, or `undefined` when a responder should wait.
	 * @throws Error if required inputs are missing or invalid.
	 */
	async start(): Promise<CPaceMessage | undefined> {
		const { suite, prs, ci, sid, ad, role, mode } = this.inputs;

		const normalizedPrs = this.ensureRequired("prs", prs, { minLength: 1 });

		// ad is always defined if you normalized in ctor; allow empty
		const normalizedAd = this.ensureRequired("ad", ad); // no minLength => empty ok

		this.emitAudit(AUDIT_CODES.CPACE_START_BEGIN, "info", { mode, role });

		const { scalar: ephemeralScalar, serialized: localMsg } =
			await computeLocalElement(suite, normalizedPrs, ci, sid);

		this.ephemeralScalar = ephemeralScalar;
		this.localMsg = localMsg;

		if (mode === "initiator-responder" && role === "responder") {
			return undefined;
		}

		const outbound: CPaceMessage = {
			type: "msg",
			payload: this.localMsg,
			ad: normalizedAd,
		};

		this.emitAudit(AUDIT_CODES.CPACE_START_SENT, "info", {
			payload_len: outbound.payload.length,
			ad_len: outbound.ad.length,
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
		const { prs, sid, ad, role, mode, suite } = this.inputs;

		this.ensureRequired("prs", prs, { minLength: 1 });

		// local AD is required semantically, but empty is allowed
		const localAd = this.ensureRequired("ad", ad); // no minLength => empty ok

		const sanitizedPeerMsg = validateAndSanitizePeerMessage(
			suite,
			msg,
			(field, value) => this.ensureRequired(field, value),
			(field, reason, extra) => this.reportInputInvalid(field, reason, extra),
		);

		await this.ensureResponderHasLocalMsg(mode, role);

		this.emitAudit(AUDIT_CODES.CPACE_RX_RECEIVED, "info", {
			payload_len: sanitizedPeerMsg.payload.length,
			ad_len: sanitizedPeerMsg.ad.length,
		});

		this.iskValue = await this.finish(sid, sanitizedPeerMsg);

		// IR responder sends its single response message (Yb, ADb)
		if (mode === "initiator-responder" && role === "responder") {
			if (!this.localMsg) {
				throw new Error("CPaceSession.receive: missing outbound message");
			}
			const response: CPaceMessage = {
				type: "msg",
				payload: this.localMsg,
				ad: localAd, // responder's ADb (may be EMPTY)
			};

			this.emitAudit(AUDIT_CODES.CPACE_START_SENT, "info", {
				payload_len: response.payload.length,
				ad_len: response.ad.length,
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

		const { suite, mode, role, ad } = this.inputs;
		const localAd = this.ensureRequired("ad", ad); // empty ok
		const peerAd = this.ensureRequired("peer ad", peerMsg.ad); // after sanitize it should exist

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
			// IR order depends on role
			if (role === "initiator") {
				transcript = makeTranscriptIR(
					"initiator",
					this.localMsg,
					localAd,
					peerMsg.payload,
					peerAd,
				);
			} else if (role === "responder") {
				transcript = makeTranscriptIR(
					"responder",
					this.localMsg,
					localAd,
					peerMsg.payload,
					peerAd,
				);
			} else {
				throw new Error(
					"CPaceSession.finish: symmetric role in initiator-responder mode",
				);
			}
		} else {
			// symmetric: ordered concatenation will canonicalize (Y,AD) pairs
			transcript = makeTranscriptOC(
				this.localMsg,
				localAd,
				peerMsg.payload,
				peerAd,
			);
		}

		const { isk, sidOutput } = await deriveIskAndSid(
			suite,
			transcript,
			sharedSecret,
			sid,
		);

		this.sidValue = sidOutput;
		this.zeroizeSecrets(sharedSecret);

		this.emitAudit(AUDIT_CODES.CPACE_FINISH_OK, "info", {
			transcript_type: mode === "initiator-responder" ? "ir" : "oc",
			sid_provided: Boolean(sid?.length),
		});

		return isk;
	}

	/** @internal */
	private async ensureResponderHasLocalMsg(
		mode: CPaceMode,
		role: CPaceRole,
	): Promise<void> {
		if (
			mode === "initiator-responder" &&
			role === "responder" &&
			!this.localMsg
		) {
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

	private buildValidationAuditExtra(ctx: {
		options?: EnsureBytesOptions;
		value: Uint8Array | undefined;
	}): {
		expected?: ReturnType<typeof extractExpected>;
		actual: number | "undefined" | null;
	} {
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
