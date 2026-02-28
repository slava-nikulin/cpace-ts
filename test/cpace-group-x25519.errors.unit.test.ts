import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";

describe("X25519Group error reporting", () => {
	it("serialize reports expected and actual lengths", () => {
		expect(() => G_X25519.serialize(new Uint8Array(31))).toThrow(
			/X25519Group\.serialize: expected 32 bytes, got 31/,
		);
		expect(() => G_X25519.serialize(new Uint8Array(33))).toThrow(
			/X25519Group\.serialize: expected 32 bytes, got 33/,
		);
	});

	it("deserialize reports expected and actual lengths", () => {
		expect(() => G_X25519.deserialize(new Uint8Array(0))).toThrow(
			/X25519Group\.deserialize: expected 32 bytes, got 0/,
		);
		expect(() => G_X25519.deserialize(new Uint8Array(34))).toThrow(
			/X25519Group\.deserialize: expected 32 bytes, got 34/,
		);
	});

	it("scalarMultVfy rejects non-canonical point lengths with context", async () => {
		await expect(
			G_X25519.scalarMultVfy(new Uint8Array(32), new Uint8Array(1)),
		).rejects.toThrow(
			/X25519Group\.scalarMultVfy: invalid point length \(expected 32 bytes, got 1\)/,
		);
		await expect(
			G_X25519.scalarMultVfy(new Uint8Array(32), new Uint8Array(64)),
		).rejects.toThrow(
			/X25519Group\.scalarMultVfy: invalid point length \(expected 32 bytes, got 64\)/,
		);
	});
});
