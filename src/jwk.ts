import { IPublicKey } from "./public-key";
import { InvalidKeyKindError } from "./invalid-key-kind.error";
import { AlgorithmKind } from "./algorithm-kind";
import * as u8a from "uint8arrays";
import * as elliptic from "elliptic";
import * as secp256k1 from "./algorithms/secp256k1";
import * as ed25519 from "./algorithms/ed25519";
import * as x25519 from "./algorithms/x25519";

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
      const x = point.slice(1, (point.length - 1) / 2 + 1);
      const y = point.slice((point.length - 1) / 2 + 1);
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

export function jwkAlgorithm(jwk: any): AlgorithmKind {
  if (jwk.kty == "EC" && jwk.crv == "secp256k1") {
    return AlgorithmKind.secp256k1;
  }
  if (jwk.kty == "OKP" && jwk.crv == "Ed25519") {
    return AlgorithmKind.ed25519;
  }
  if (jwk.kty == "OKP" && jwk.crv == "X25519") {
    return AlgorithmKind.x25519;
  }
  throw new Error(`Can not handle JWK`);
}

export function fromJWK(jwk: any) {
  const algorithm = jwkAlgorithm(jwk);
  switch (algorithm) {
    case AlgorithmKind.x25519: {
      const material = u8a.fromString(jwk.x, "base64url");
      return new x25519.PublicKey(material);
    }
    case AlgorithmKind.ed25519: {
      const material = u8a.fromString(jwk.x, "base64url");
      return new ed25519.PublicKey(material);
    }
    case AlgorithmKind.secp256k1: {
      const x = u8a.fromString(jwk.x, "base64url");
      const y = u8a.fromString(jwk.y, "base64url");
      const uncompressed = u8a.concat([new Uint8Array([4]), x, y]);
      const material = new Uint8Array(
        secp256k1Context
          .keyFromPublic(uncompressed)
          .getPublic()
          .encode("array", true)
      );
      return new secp256k1.PublicKey(material);
    }
    default:
      throw new InvalidKeyKindError(algorithm);
  }
}
