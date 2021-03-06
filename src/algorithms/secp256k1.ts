import * as elliptic from "elliptic";
import * as sha256 from "@stablelib/sha256";
import BN from "bn.js";
import { IPublicKey, ISignatureVerification } from "../public-key";
import { AlgorithmKind } from "../algorithm-kind";
import { IPrivateKey, ISigner } from "../private-key";
import * as uint8arrays from "uint8arrays";
import { InvalidKeyMaterialError } from "../invalid-key-material.error";

const secp256k1Context = new elliptic.ec("secp256k1");

export class PublicKey implements IPublicKey, ISignatureVerification {
  readonly kind = AlgorithmKind.secp256k1;
  constructor(readonly material: Uint8Array) {}

  async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
    try {
      const keyPair = secp256k1Context.keyFromPublic(this.material);
      const r = new BN(signature.slice(0, 32));
      const s = new BN(signature.slice(32, 64));
      const digest = sha256.hash(message);
      return keyPair.verify(digest, { r, s });
    } catch {
      return false;
    }
  }
}

export class PrivateKey implements IPrivateKey, ISigner {
  readonly kind = AlgorithmKind.secp256k1;

  #keyPair: elliptic.ec.KeyPair;
  #publicKey: Uint8Array;

  constructor(material: Uint8Array) {
    if (material.length !== 32) {
      throw new InvalidKeyMaterialError(
        AlgorithmKind.secp256k1,
        `Expect private key material to be 32 bytes, got ${material.length}`
      );
    }
    this.#keyPair = secp256k1Context.keyFromPrivate(material);
    this.#publicKey = new Uint8Array(
      this.#keyPair.getPublic().encodeCompressed()
    );
  }

  async publicKey(): Promise<PublicKey> {
    return new PublicKey(this.#publicKey);
  }

  async sign(message: Uint8Array): Promise<Uint8Array> {
    const digest = sha256.hash(message);
    const signature = this.#keyPair.sign(digest, { canonical: true });
    const r = new Uint8Array(signature.r.toArray("be", 32));
    const s = new Uint8Array(signature.s.toArray("be", 32));
    return uint8arrays.concat([r, s]);
  }
}
