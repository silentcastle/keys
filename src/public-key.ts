import { KeyKind } from "./key-kind";

export interface IPublicKey {
  readonly kind: KeyKind;
  readonly material: Uint8Array;
}

export interface ISignatureVerification {
  verify(message: Uint8Array, signature: Uint8Array): Promise<boolean>;
}
