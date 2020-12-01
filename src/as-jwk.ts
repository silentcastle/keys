import { IPublicKey } from "./public-key";
import { InvalidKeyKindError } from "./invalid-key-kind.error";
import { AlgorithmKind } from "./algorithm-kind";
import * as u8a from "uint8arrays";
import * as elliptic from "elliptic";

const secp256k1Context = new elliptic.ec("secp256k1");

export function asJWK(p: IPublicKey) {
  switch (p.kind) {
    case AlgorithmKind.secp256k1: {
      const point = new Uint8Array(
        secp256k1Context
          .keyFromPublic(p.material)
          .getPublic()
          .encode("array", false)
      );
      let x = point.slice(1, (point.length - 1) / 2 + 1);
      let y = point.slice((point.length - 1) / 2 + 1);
      return {
        kty: "EC",
        crv: "secp256k1",
        x: u8a.toString(x, "base64url"),
        y: u8a.toString(y, "base64url"),
      };
    }
    case AlgorithmKind.ed25519: {
      return {
        crv: "Ed25519",
        kty: "OKP",
        x: u8a.toString(p.material, "base64url"),
      };
    }
    case AlgorithmKind.x25519: {
      return {
        kty: "OKP",
        crv: "X25519",
        x: u8a.toString(p.material, "base64url"),
      };
    }
    default:
      throw new InvalidKeyKindError(p.kind);
  }
}
