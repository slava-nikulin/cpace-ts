import { describe, expect, it } from "vitest";
import type { GroupEnv } from "../src/cpace-group-x25519";
import {
	type CPaceInputs,
	CPaceSession,
	type CPaceSuiteDesc,
	InvalidPeerElementError,
} from "../src/cpace-session";

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
		DSI: new Uint8Array([0x43, 0x50]), // "CP"
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

function createSessionWithGroup(group: GroupEnv): CPaceSession {
	const suite: CPaceSuiteDesc = {
		name: "MockSuite",
		group,
		hash: mockHash,
	};

	const inputs: CPaceInputs = {
		prs: new Uint8Array([1, 2, 3]),
		suite,
		mode: "initiator-responder",
		role: "initiator",
	};

	return new CPaceSession(inputs);
}

describe("CPaceSession.finish invalid peer handling", () => {
	it("wraps scalarMultVfy errors as InvalidPeerElementError", async () => {
		const group = createMockGroup(async () => {
			throw new Error("low-order");
		});
		const session = createSessionWithGroup(group);

		await session.start();

		await expect(
			session.receive({
				type: "msg",
				payload: new Uint8Array(32),
				ad: new Uint8Array(0),
			}),
		).rejects.toBeInstanceOf(InvalidPeerElementError);
	});

	it("rejects when scalarMultVfy returns the neutral element", async () => {
		const neutral = new Uint8Array(32);
		const group = createMockGroup(async () => neutral, { I: neutral });
		const session = createSessionWithGroup(group);

		await session.start();

		await expect(
			session.receive({
				type: "msg",
				payload: new Uint8Array(32),
				ad: new Uint8Array(0),
			}),
		).rejects.toBeInstanceOf(InvalidPeerElementError);
	});

	it("produces an ISK for valid peer elements", async () => {
		const group = createMockGroup(async () => new Uint8Array(32).fill(9));
		const session = createSessionWithGroup(group);

		await session.start();
		await session.receive({
			type: "msg",
			payload: new Uint8Array(32),
			ad: new Uint8Array(0),
		});

		const isk = session.exportISK();
		expect(isk.length).toBeGreaterThan(0);
		expect(session.sidOutput).toBeDefined();
	});

	it("throws a descriptive error when finish is invoked before start", async () => {
		const group = createMockGroup(async () => new Uint8Array(32).fill(2));
		const session = createSessionWithGroup(group);

		await expect(
			session.receive({
				type: "msg",
				payload: new Uint8Array(32),
				ad: new Uint8Array(0),
			}),
		).rejects.toThrow("CPaceSession.finish: session not started");
	});
});
