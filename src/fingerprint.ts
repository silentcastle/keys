import * as multicodec from "multicodec";
import { IPublicKey } from "./public-key";
import { AlgorithmKind } from "./algorithm-kind";
import { InvalidKeyKindError } from "./invalid-key-kind.error";
import * as multibase from "multibase";

export enum KEY_PREFIX {
  secp256k1 = 0xe7,
  x25519 = 0xec,
  ed25519 = 0xed,
}

const decoder = new TextDecoder();

function encodeWithPrefix(prefix: number, material: Uint8Array) {
  const bytes = multicodec.addPrefix(Uint8Array.from([prefix]), material);
  const encoded = multibase.encode("base58btc", bytes);
  return decoder.decode(encoded);
}

export function fingerprint(publicKey: IPublicKey): string {
  switch (publicKey.kind) {
    case AlgorithmKind.ed25519:
      return encodeWithPrefix(KEY_PREFIX.ed25519, publicKey.material);
    case AlgorithmKind.secp256k1:
      return encodeWithPrefix(KEY_PREFIX.secp256k1, publicKey.material);
    case AlgorithmKind.x25519:
      return encodeWithPrefix(KEY_PREFIX.x25519, publicKey.material);
    default:
      throw new InvalidKeyKindError(publicKey.kind);
  }
}
