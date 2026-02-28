export class InvalidPeerElementError extends Error {
	constructor(
		message = "CPaceSession: invalid peer element",
		options?: ErrorOptions,
	) {
		super(message, options);
		this.name = "InvalidPeerElementError";
	}
}
