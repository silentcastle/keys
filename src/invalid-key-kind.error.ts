/**
 * Used for exhaustive matching while selecting between [[KeyKind]] variants.
 */
export class InvalidKeyKindError extends Error {
  /**
   * @param kind Turns into message like `Invalid key kind <kind>`.
   */
  constructor(kind: never) {
    super(`Invalid key kind ${kind}`);
  }
}
