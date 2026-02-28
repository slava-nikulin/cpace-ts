import { describe, expect, it } from "vitest";
import type { GroupEnv } from "../src/cpace-group-x25519";
import { LowOrderPointError } from "../src/cpace-group-x25519";
import type { CPaceSuiteDesc } from "../src/cpace-session";
import {
	type AuditEvent,
	type AuditLogger,
	CPaceSession,
	InvalidPeerElementError,
} from "../src/cpace-session";
import { expectDefined } from "./helpers";

class CollectingAuditLogger implements AuditLogger {
	readonly events: AuditEvent[] = [];

	audit(event: AuditEvent): void {
		this.events.push(event);
	}
}

type ScalarMultVfyImpl = (
	group: GroupEnv,
	scalar: Uint8Array,
	point: Uint8Array,
) => Promise<Uint8Array>;

function createMockGroup(
	scalarMultVfyImpl: ScalarMultVfyImpl,
	options: { I?: Uint8Array } = {},
): GroupEnv {
	const fieldSize = 32;
	const generator = new Uint8Array(fieldSize).fill(5);
	const neutral = options.I ?? new Uint8Array(fieldSize);
	const scalarValue = new Uint8Array(fieldSize).fill(7);
	const serialized = new Uint8Array(fieldSize).fill(11);

	const group: GroupEnv = {
		name: "MockGroup",
		fieldSizeBytes: fieldSize,
		fieldSizeBits: fieldSize * 8,
		sInBytes: 64,
		I: neutral,
		DSI: new Uint8Array([0x43, 0x50]),
		calculateGenerator: async () => generator.slice(),
		sampleScalar: () => scalarValue.slice(),
		scalarMult: async () => serialized.slice(),
		scalarMultVfy: async (scalar, point) =>
			scalarMultVfyImpl(group, scalar, point),
		serialize: (point) => point.slice(),
		deserialize: (buf) => buf.slice(),
	};

	return group;
}

const mockHash = async (input: Uint8Array): Promise<Uint8Array> => {
	const out = new Uint8Array(32);
	for (let i = 0; i < out.length; i += 1) {
		out[i] = input[i % input.length] ?? 0;
	}
	return out;
};

function createSuite(group: GroupEnv): CPaceSuiteDesc {
	return { name: "MockSuite", group, hash: mockHash };
}

describe("CPaceSession audit logging", () => {
	it("emits standard audit trail on symmetric success", async () => {
		const scalarResult = new Uint8Array(32).fill(9);
		const group = createMockGroup(async () => scalarResult.slice());
		const suite = createSuite(group);

		const loggerA = new CollectingAuditLogger();
		const loggerB = new CollectingAuditLogger();

		const sessionA = new CPaceSession({
			prs: new Uint8Array([1, 2, 3]),
			suite,
			mode: "symmetric",
			role: "symmetric",
			audit: loggerA,
		});
		const sessionB = new CPaceSession({
			prs: new Uint8Array([1, 2, 3]),
			suite,
			mode: "symmetric",
			role: "symmetric",
			audit: loggerB,
		});

		const aMsg = expectDefined(await sessionA.start(), "A message");
		const bMsg = expectDefined(await sessionB.start(), "B message");

		await sessionA.receive(bMsg);
		await sessionB.receive(aMsg);

		expect(loggerA.events.map((e) => e.code)).toEqual([
			"CPACE_SESSION_CREATED",
			"CPACE_START_BEGIN",
			"CPACE_START_SENT",
			"CPACE_RX_RECEIVED",
			"CPACE_FINISH_BEGIN",
			"CPACE_FINISH_OK",
		]);
		const finishOk = loggerA.events.find((e) => e.code === "CPACE_FINISH_OK");
		expect(finishOk?.data).toMatchObject({
			transcript_type: "oc",
			sid_provided: false,
		});
	});

	it("records CPACE_INPUT_INVALID for wrong peer payload length", async () => {
		const group = createMockGroup(async () => new Uint8Array(32).fill(3));
		const suite = createSuite(group);
		const audit = new CollectingAuditLogger();
		const session = new CPaceSession({
			prs: new Uint8Array([1, 2, 3]),
			suite,
			mode: "initiator-responder",
			role: "initiator",
			audit,
		});

		expectDefined(await session.start(), "initiator start");

		await expect(
			session.receive({
				type: "msg",
				payload: new Uint8Array(1),
				ad: new Uint8Array(0),
			}),
		).rejects.toBeInstanceOf(InvalidPeerElementError);

		const invalid = audit.events.find((e) => e.code === "CPACE_INPUT_INVALID");
		expect(invalid).toBeDefined();
		expect(invalid?.data).toMatchObject({
			field: "peer.payload",
			actual: 1,
		});
	});

	it("records CPACE_INPUT_INVALID when peer ad is not a Uint8Array", async () => {
		const scalarResult = new Uint8Array(32).fill(6);
		const group = createMockGroup(async () => scalarResult.slice());
		const suite = createSuite(group);
		const audit = new CollectingAuditLogger();

		const session = new CPaceSession({
			prs: new Uint8Array([1, 2, 3]),
			suite,
			mode: "symmetric",
			role: "symmetric",
			audit,
		});
		const peer = new CPaceSession({
			prs: new Uint8Array([1, 2, 3]),
			suite,
			mode: "symmetric",
			role: "symmetric",
		});

		expectDefined(await session.start(), "session start");
		const peerMsg = expectDefined(await peer.start(), "peer start");

		await expect(
			session.receive({
				type: "msg",
				payload: peerMsg.payload,
				ad: undefined as unknown as Uint8Array,
			}),
		).rejects.toThrow(/peer ad must be a Uint8Array/);

		const invalid = audit.events.find((e) => {
			if (e.code !== "CPACE_INPUT_INVALID") return false;
			const data = e.data as { field?: string } | undefined;
			return data?.field === "peer.ad";
		});
		expect(invalid).toBeDefined();
	});

	it("records CPACE_LOW_ORDER_POINT when scalar multiplication yields zero", async () => {
		const group = createMockGroup(async () => {
			throw new LowOrderPointError("low order", { reason: "low-order" });
		});
		const suite = createSuite(group);
		const audit = new CollectingAuditLogger();
		const session = new CPaceSession({
			prs: new Uint8Array([1, 2, 3]),
			suite,
			mode: "initiator-responder",
			role: "initiator",
			audit,
		});

		expectDefined(await session.start(), "start message");

		await expect(
			session.receive({
				type: "msg",
				payload: new Uint8Array(32),
				ad: new Uint8Array(0),
			}),
		).rejects.toBeInstanceOf(InvalidPeerElementError);

		const lowOrder = audit.events.find(
			(e) => e.code === "CPACE_LOW_ORDER_POINT",
		);
		expect(lowOrder).toBeDefined();
	});
});
