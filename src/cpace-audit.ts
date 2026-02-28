import { cleanObject } from "./cpace-validation";

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

export const AUDIT_CODES = Object.freeze({
	CPACE_SESSION_CREATED: "CPACE_SESSION_CREATED",
	CPACE_START_BEGIN: "CPACE_START_BEGIN",
	CPACE_START_SENT: "CPACE_START_SENT",
	CPACE_RX_RECEIVED: "CPACE_RX_RECEIVED",
	CPACE_FINISH_BEGIN: "CPACE_FINISH_BEGIN",
	CPACE_FINISH_OK: "CPACE_FINISH_OK",
	CPACE_INPUT_INVALID: "CPACE_INPUT_INVALID",
	CPACE_PEER_INVALID: "CPACE_PEER_INVALID",
	CPACE_LOW_ORDER_POINT: "CPACE_LOW_ORDER_POINT",
} as const);

export function emitAuditEvent(
	logger: AuditLogger | undefined,
	sessionId: string,
	code: string,
	level: AuditLevel,
	data?: Record<string, unknown>,
) {
	if (!logger) return;
	const cleaned = cleanObject(data);
	const event: AuditEvent = {
		ts: new Date().toISOString(),
		sessionId,
		level,
		code,
		...(cleaned ? { data: cleaned } : {}),
	};
	void logger.audit(event);
}
