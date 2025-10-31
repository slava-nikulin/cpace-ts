// test/cpace-testvectors-b1-loworder.ts

// маленький локальный хелпер, чтобы не тащить из src
export function hexToBytes(hex: string): Uint8Array {
	const clean = hex.trim().toLowerCase();
	const out = new Uint8Array(clean.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

// s из драфта B.1.10
export const TC_LOW_S = hexToBytes(
	"af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff",
);

// u0 ... ub — ровно как в драфте
export const TC_U0 = hexToBytes(
	"0000000000000000000000000000000000000000000000000000000000000000",
);
export const TC_U1 = hexToBytes(
	"0100000000000000000000000000000000000000000000000000000000000000",
);
export const TC_U2 = hexToBytes(
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
);
export const TC_U3 = hexToBytes(
	"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
);
export const TC_U4 = hexToBytes(
	"5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
);
export const TC_U5 = hexToBytes(
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
);
export const TC_U6 = hexToBytes(
	"daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);
export const TC_U7 = hexToBytes(
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
);
export const TC_U8 = hexToBytes(
	"dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);
export const TC_U9 = hexToBytes(
	"d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);
export const TC_UA = hexToBytes(
	"cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
);
export const TC_UB = hexToBytes(
	"4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
);

// ожидания q0 ... qb — тоже прямо из драфта
export const TC_Q0 = hexToBytes(
	"0000000000000000000000000000000000000000000000000000000000000000",
);
export const TC_Q1 = hexToBytes(
	"0000000000000000000000000000000000000000000000000000000000000000",
);
export const TC_Q2 = hexToBytes(
	"0000000000000000000000000000000000000000000000000000000000000000",
);
export const TC_Q3 = hexToBytes(
	"0000000000000000000000000000000000000000000000000000000000000000",
);
export const TC_Q4 = hexToBytes(
	"0000000000000000000000000000000000000000000000000000000000000000",
);
export const TC_Q5 = hexToBytes(
	"0000000000000000000000000000000000000000000000000000000000000000",
);
export const TC_Q6 = hexToBytes(
	"d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806",
);
export const TC_Q7 = hexToBytes(
	"0000000000000000000000000000000000000000000000000000000000000000",
);
export const TC_Q8 = hexToBytes(
	"c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38",
);
export const TC_Q9 = hexToBytes(
	"db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456",
);
export const TC_QA = hexToBytes(
	"e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a",
);
export const TC_QB = hexToBytes(
	"993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175",
);
