import { AlgorithmKind } from "./algorithm-kind";

export class InvalidKeyMaterialError extends Error {
  constructor(readonly kind: AlgorithmKind, readonly message: string) {
    super();
  }
}
