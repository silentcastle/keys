export * from "./algorithm-kind";
export * from "./invalid-key-kind.error";
export * from "./private-key.factory";
export * from "./public-key";
export * from "./private-key";
export * from "./fingerprint";

import * as secp256k1 from "./algorithms/secp256k1";
import * as ed25519 from "./algorithms/ed25519";

export const algorithms = { secp256k1, ed25519 };
