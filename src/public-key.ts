import { AlgorithmKind } from "./algorithm-kind";

export interface IPublicKey {
  readonly kind: AlgorithmKind;
  readonly material: Uint8Array;
}

export interface ISignatureVerification {
  verify(message: Uint8Array, signature: Uint8Array): Promise<boolean>;
}

export interface IEncrypt {
  encrypt(message: Uint8Array): Promise<boolean>;
}
