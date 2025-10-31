import { compareBytes } from "./bytes";
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
import type { HashFn } from "./hash";

const MAX_INPUT_LENGTH = 0xffff;

type EnsureBytesOptions = {
	optional?: boolean;
	minLength?: number;
	maxLength?: number;
};

function ensureBytes(
	name: string,
	value: Uint8Array | undefined,
	{
		optional = true,
		minLength = 0,
		maxLength = MAX_INPUT_LENGTH,
	}: EnsureBytesOptions = {},
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

export type AuditLevel = "info" | "warn" | "error" | "security";

export type AuditEvent = {
	ts: string;
	sessionId: string;
	level: AuditLevel;
	code: string;
	message?: string;
	data?: Record<string, unknown>;
};

export interface AuditLogger {
	audit(event: AuditEvent): void | Promise<void>;
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
		const normalizedCi =
			ci !== undefined ? this.ensureField("ci", ci) : undefined;
		const normalizedSid =
			sid !== undefined ? this.ensureField("sid", sid) : undefined;
		const normalizedAda =
			ada !== undefined ? this.ensureField("ada", ada) : undefined;
		const normalizedAdb =
			adb !== undefined ? this.ensureField("adb", adb) : undefined;

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

		const normalizedPrs = this.ensureField("prs", prs, {
			optional: false,
			minLength: 1,
		});
		const normalizedCi =
			ci !== undefined ? this.ensureField("ci", ci) : undefined;
		const normalizedSid =
			sid !== undefined ? this.ensureField("sid", sid) : undefined;
		const normalizedSessionAdb =
			adb !== undefined ? this.ensureField("adb", adb) : undefined;

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
		const peerAda = hasPeerAda
			? this.ensureField("peer ada", msg.ada)
			: undefined;
		const peerAdb = hasPeerAdb
			? this.ensureField("peer adb", msg.adb)
			: undefined;

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
			ada !== undefined ? this.ensureField("ada", ada) : undefined;
		const normalizedAdb =
			adb !== undefined ? this.ensureField("adb", adb) : undefined;

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
			const hasPeerAda = peerMsg.ada !== undefined;
			const hasPeerAdb = peerMsg.adb !== undefined;
			const peerAdaBytes = hasPeerAda
				? this.ensureField("peer ada", peerMsg.ada)
				: undefined;
			const peerAdbBytes = hasPeerAdb
				? this.ensureField("peer adb", peerMsg.adb)
				: undefined;
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
		options?: EnsureBytesOptions,
	): Uint8Array {
		try {
			return ensureBytes(field, value, options);
		} catch (err) {
			this.reportInputInvalid(
				field,
				err instanceof Error ? err.message : "validation failed",
				{
					expected: extractExpected(options),
					actual:
						value instanceof Uint8Array
							? value.length
							: value === undefined
								? "undefined"
								: null,
				},
			);
			throw err;
		}
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
		if (!this.auditLogger) return;
		const cleaned = cleanObject(data);
		const event: AuditEvent = {
			ts: new Date().toISOString(),
			sessionId: this.sessionId,
			level,
			code,
			...(cleaned ? { data: cleaned } : {}),
		};
		void this.auditLogger.audit(event);
	}
}

function cleanObject(
	data?: Record<string, unknown>,
): Record<string, unknown> | undefined {
	if (!data) return undefined;
	const cleaned: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(data)) {
		if (value === undefined) continue;
		cleaned[key] = value;
	}
	return cleaned;
}

type ExpectedRange = {
	min?: number;
	max?: number;
};

function extractExpected(
	options?: EnsureBytesOptions,
): ExpectedRange | undefined {
	if (!options) return undefined;
	const expected: ExpectedRange = {};
	if (options.minLength !== undefined) expected.min = options.minLength;
	if (options.maxLength !== undefined) expected.max = options.maxLength;
	return Object.keys(expected).length > 0 ? expected : undefined;
}

function generateSessionId(): string {
	const length = 16;
	const bytes = new Uint8Array(length);
	if (
		typeof globalThis.crypto !== "undefined" &&
		typeof globalThis.crypto.getRandomValues === "function"
	) {
		globalThis.crypto.getRandomValues(bytes);
	} else {
		for (let i = 0; i < length; i += 1) {
			bytes[i] = Math.floor(Math.random() * 256);
		}
	}
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function isLowOrderError(
	err: unknown,
	reason: LowOrderPointReason,
): err is LowOrderPointError {
	return err instanceof LowOrderPointError && err.reason === reason;
}
