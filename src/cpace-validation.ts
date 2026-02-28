const MAX_INPUT_LENGTH = Number.MAX_SAFE_INTEGER;

export type EnsureBytesOptions = {
	optional?: boolean;
	minLength?: number;
	maxLength?: number;
};

export type EnsureFieldErrorHandler = (
	err: unknown,
	context: {
		field: string;
		value: Uint8Array | undefined;
		options?: EnsureBytesOptions;
	},
) => void;

export function ensureBytes(
	name: string,
	value: Uint8Array | undefined,
	{
		optional = true,
		minLength = 0,
		maxLength = MAX_INPUT_LENGTH,
	}: EnsureBytesOptions = {},
): Uint8Array {
	if (!Number.isSafeInteger(maxLength) || maxLength < 0) {
		throw new RangeError(
			`CPaceSession: ${name} maxLength must be a non-negative safe integer`,
		);
	}

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

export function ensureField(
	field: string,
	value: Uint8Array | undefined,
	options?: EnsureBytesOptions,
	onError?: EnsureFieldErrorHandler,
): Uint8Array {
	try {
		return ensureBytes(field, value, options);
	} catch (err) {
		const context =
			options === undefined ? { field, value } : { field, value, options };
		onError?.(err, context);
		throw err;
	}
}

export type ExpectedRange = {
	min?: number;
	max?: number;
};

export function extractExpected(
	options?: EnsureBytesOptions,
): ExpectedRange | undefined {
	if (!options) return undefined;
	const expected: ExpectedRange = {};
	if (options.minLength !== undefined) expected.min = options.minLength;
	if (options.maxLength !== undefined) expected.max = options.maxLength;
	return Object.keys(expected).length > 0 ? expected : undefined;
}

export function cleanObject(
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

export function generateSessionId(): string {
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
