export * from "./algorithm-kind";
export * from "./invalid-key-kind.error";
export * from "./private-key.factory";
export * from "./public-key";
export * from "./private-key";
export * from "./fingerprint";

import * as secp256k1Import from "./algorithms/secp256k1";
import * as ed25519Import from "./algorithms/ed25519";

export namespace algorithms {
  export const secp256k1 = secp256k1Import;
  export const ed25519 = ed25519Import;
}
