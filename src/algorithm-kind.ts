import { InvalidKeyKindError } from "./invalid-key-kind.error";

export enum AlgorithmKind {
  secp256k1 = "secp256k1",
  ed25519 = "ed25519",
  x25519 = "x25519",
}

export namespace AlgorithmKind {
  export function fromString(s: string) {
    const maybe = s as AlgorithmKind;
    switch (maybe) {
      case AlgorithmKind.secp256k1:
        return AlgorithmKind.secp256k1;
      case AlgorithmKind.ed25519:
        return AlgorithmKind.ed25519;
      case AlgorithmKind.x25519:
        return AlgorithmKind.x25519;
      default:
        throw new InvalidKeyKindError(maybe);
    }
  }
}
