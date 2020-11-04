import { KeyKind } from "./key-kind";
import { IPublicKey } from "./public-key";

export interface IPrivateKey {
  readonly kind: KeyKind;
  publicKey(): Promise<IPublicKey>;
}

export interface ISigner {
  kind: KeyKind;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface ISignerIdentified extends ISigner {
  kid: string;
}
