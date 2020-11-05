import * as sha256 from "@stablelib/sha256";
import * as secp256k1 from "./algorithms/secp256k1";
import * as ed25519 from "./algorithms/ed25519";
import { AlgorithmKind } from "./algorithm-kind";
import { IPrivateKey } from "./private-key";
import { InvalidKeyKindError } from "./invalid-key-kind.error";
import * as uint8arrays from "uint8arrays";

export class PrivateKeyFactory {
  fromSeed(
    kind: AlgorithmKind.secp256k1,
    seed: Uint8Array | string
  ): secp256k1.PrivateKey;
  fromSeed(
    kind: AlgorithmKind.ed25519,
    seed: Uint8Array | string
  ): ed25519.PrivateKey;
  fromSeed(kind: AlgorithmKind, seed: Uint8Array | string): IPrivateKey {
    const bytes =
      typeof seed === "string" ? uint8arrays.fromString(seed) : seed;
    const secret = sha256.hash(bytes);
    switch (kind) {
      case AlgorithmKind.ed25519:
        return this.fromSecret(kind, secret);
      case AlgorithmKind.secp256k1:
        return this.fromSecret(kind, secret);
      /* istanbul ignore next */
      default:
        throw new InvalidKeyKindError(kind);
    }
  }

  fromSecret(kind: AlgorithmKind.secp256k1, secret: Uint8Array): secp256k1.PrivateKey;
  fromSecret(
    kind: AlgorithmKind.ed25519,
    secret: Uint8Array
  ): ed25519.PrivateKey;
  fromSecret(kind: AlgorithmKind, secret: Uint8Array): IPrivateKey {
    switch (kind) {
      case AlgorithmKind.ed25519:
        return new ed25519.PrivateKey(secret);
      case AlgorithmKind.secp256k1:
        return new secp256k1.PrivateKey(secret);
      /* istanbul ignore next */
      default:
        throw new InvalidKeyKindError(kind);
    }
  }
}
