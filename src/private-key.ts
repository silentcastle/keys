import { AlgorithmKind } from "./algorithm-kind";
import { IPublicKey } from "./public-key";

export interface IPrivateKey {
  readonly kind: AlgorithmKind;
  publicKey(): Promise<IPublicKey>;
}

export interface ISigner {
  kind: AlgorithmKind;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface ISignerIdentified extends ISigner {
  kid: string;
}
