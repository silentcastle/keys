import * as sha256 from "@stablelib/sha256";
import * as es256k from "./algorithms/es256k";
import * as ed25519 from "./algorithms/ed25519";
import { KeyKind } from "./key-kind";
import { IPrivateKey } from "./private-key";
import { InvalidKeyKindError } from "./invalid-key-kind.error";
import * as uint8arrays from 'uint8arrays'

export class PrivateKeyFactory {
  fromSeed(kind: KeyKind.es256k, seed: Uint8Array | string): es256k.PrivateKey;
  fromSeed(
    kind: KeyKind.ed25519,
    seed: Uint8Array | string
  ): ed25519.PrivateKey;
  fromSeed(kind: KeyKind, seed: Uint8Array | string): IPrivateKey {
    const bytes = typeof seed === "string" ? uint8arrays.fromString(seed) : seed;
    const material = sha256.hash(bytes);
    switch (kind) {
      case KeyKind.ed25519:
        return new ed25519.PrivateKey(material);
      case KeyKind.es256k:
        return new es256k.PrivateKey(material);
      /* istanbul ignore next */
      default:
        throw new InvalidKeyKindError(kind);
    }
  }
}
