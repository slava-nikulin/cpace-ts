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
