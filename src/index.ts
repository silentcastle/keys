export * from "./algorithm-kind";
export * from "./invalid-key-kind.error";
export * from "./private-key.factory";
export * from "./public-key";
export * from "./private-key";

import * as es256k from "./algorithms/es256k";
import * as ed25519 from "./algorithms/ed25519";

export const algorithms = { es256k, ed25519 };
