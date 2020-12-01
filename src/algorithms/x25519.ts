import { IPublicKey } from "../public-key";
import { AlgorithmKind } from "../algorithm-kind";
import { IPrivateKey } from "../private-key";
import * as x25519 from "@stablelib/x25519";

export class PublicKey implements IPublicKey {
  readonly kind = AlgorithmKind.x25519;
  constructor(readonly material: Uint8Array) {}
}

export class PrivateKey implements IPrivateKey {
  readonly kind = AlgorithmKind.x25519;
  readonly #keyPair: x25519.KeyPair;

  constructor(material: Uint8Array) {
    this.#keyPair = x25519.generateKeyPairFromSeed(material);
  }

  async publicKey(): Promise<PublicKey> {
    return new PublicKey(this.#keyPair.publicKey);
  }
}
