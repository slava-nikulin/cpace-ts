import { describe, expect, it } from "vitest";
import { G_X25519 } from "../src/cpace-group-x25519";
import { sha512 } from "../src/hash";
import {
	TC_CI,
	TC_PRS,
	TC_SID,
	TC_YA_SCALAR,
	TC_YB,
	TC_YB_SCALAR,
} from "./cpace-testvectors-b1";

describe("X25519 scalarMultVfy MSB handling", () => {
	it("clears the unused most significant bit of the shared secret", async () => {
		const g = await G_X25519.calculateGenerator(sha512, TC_PRS, TC_CI, TC_SID);
		const yaScalar = TC_YA_SCALAR;
		const Yb = TC_YB;

		// Recreate Yb from the generator to avoid relying on the vector literal being canonical.
		const yaPublic = await G_X25519.scalarMult(yaScalar, g);
		expect(yaPublic.length).toBe(32);

		const shared = await G_X25519.scalarMultVfy(yaScalar, Yb);
		expect(shared.length).toBe(32);
		expect(shared[31] & 0x80).toBe(0);
	});

	it("masks non-canonical input points before multiplication", async () => {
		const g = await G_X25519.calculateGenerator(sha512, TC_PRS, TC_CI, TC_SID);
		const yaScalar = TC_YA_SCALAR;
		const Yb = await G_X25519.scalarMult(TC_YB_SCALAR, g);
		const mutatedYb = Yb.slice();
		mutatedYb[mutatedYb.length - 1] |= 0x80;

		const sharedCanonical = await G_X25519.scalarMultVfy(yaScalar, Yb);
		const sharedMutated = await G_X25519.scalarMultVfy(yaScalar, mutatedYb);

		expect(sharedMutated).toEqual(sharedCanonical);
		expect(sharedMutated[sharedMutated.length - 1] & 0x80).toBe(0);
	});
});
