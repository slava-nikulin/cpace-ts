import type { CryptoBackend } from "./crypto-backend";

export type CPaceRole = "initiator" | "responder";

export type CPaceMessage =
	| { type: "m1"; payload: Uint8Array }
	| { type: "m2"; payload: Uint8Array }
	| { type: "m3"; payload: Uint8Array };

export class CPaceSession {
	private role: CPaceRole;
	private password: Uint8Array;
	private sessionId: Uint8Array;
	private backend: CryptoBackend;
	private state: "init" | "sent-m1" | "sent-m2" | "done";
	private sharedKey: Uint8Array | null;

	constructor(opts: {
		role: CPaceRole;
		password: Uint8Array;
		sessionId: Uint8Array;
		backend: CryptoBackend;
	}) {
		this.role = opts.role;
		this.password = opts.password;
		this.sessionId = opts.sessionId;
		this.backend = opts.backend;
		this.state = "init";
		this.sharedKey = null;
	}

	// инициатор зовёт это первым
	start(): CPaceMessage {
		// TODO: реализовать шаг из драфта:
		// - сгенерировать эпhemeral
		// - замапить пароль + sessionId в элемент группы
		// - вывести m1
		this.state = "sent-m1";
		return { type: "m1", payload: new Uint8Array() }; // заглушка
	}

	// вызывается когда мы получили сообщение пира.
	// должен вернуть следующее наше сообщение (или null если мы закончили).
	next(_peer: CPaceMessage): CPaceMessage | null {
		// TODO: логика state machine CPace
		// после финального раунда вызываем internal finalize() -> this.sharedKey
		this.state = "done";
		this.sharedKey = new Uint8Array(); // заглушка
		return null;
	}

	getSharedKey(): Uint8Array {
		if (this.state !== "done" || this.sharedKey == null) {
			throw new Error("CPaceSession not complete");
		}
		return this.sharedKey;
	}
}
