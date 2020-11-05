import * as ed25519 from "@stablelib/ed25519";
import { IPublicKey, ISignatureVerification } from "../public-key";
import { AlgorithmKind } from "../algorithm-kind";
import { IPrivateKey, ISigner } from "../private-key";
import { InvalidKeyMaterialError } from "../invalid-key-material.error";

export class PublicKey implements IPublicKey, ISignatureVerification {
  readonly kind = AlgorithmKind.ed25519;
  constructor(readonly material: Uint8Array) {}

  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    try {
      return ed25519.verify(this.material, message, signature);
    } catch {
      return false;
    }
  }
}

export class PrivateKey implements IPrivateKey, ISigner {
  readonly kind = AlgorithmKind.ed25519;
  #keyPair: ed25519.KeyPair;
  #publicKey: Uint8Array;

  constructor(material: Uint8Array) {
    if (material.length !== 32) {
      throw new InvalidKeyMaterialError(
        AlgorithmKind.ed25519,
        `Expect private key material to be 32 bytes, got ${material.length}`
      );
    }
    this.#keyPair = ed25519.generateKeyPairFromSeed(material as Buffer);
    this.#publicKey = this.#keyPair.publicKey;
  }

  async publicKey(): Promise<PublicKey> {
    return new PublicKey(this.#publicKey);
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    return ed25519.sign(this.#keyPair.secretKey, message);
  }
}
