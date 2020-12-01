import { PrivateKeyFactory } from "../private-key.factory";
import { AlgorithmKind } from "../algorithm-kind";
import * as u8a from "uint8arrays";
import secp256k1 from "./secp256k1.json";
import ed25519 from "./ed25519.json";
import x25519 from "./x25519.json";
import { fingerprint } from "../fingerprint";
import { asJWK, fromJWK } from "../jwk";

const keyFactory = new PrivateKeyFactory();

test("secp256k1", async () => {
  for (let vector of secp256k1) {
    const secret = u8a.fromString(vector.seed, "base16");
    const privateKey = keyFactory.fromSecret(AlgorithmKind.secp256k1, secret);
    const publicKey = await privateKey.publicKey();
    expect(fingerprint(publicKey)).toEqual(vector.fingerprint);
    expect(asJWK(publicKey)).toEqual(vector.publicKeyJwk);
    expect(fromJWK(asJWK(publicKey))).toEqual(publicKey);
  }
});

test("ed25519", async () => {
  for (let vector of ed25519) {
    const secret = u8a.fromString(vector.seed, "base16");
    const privateKey = keyFactory.fromSecret(AlgorithmKind.ed25519, secret);
    const publicKey = await privateKey.publicKey();
    expect(fingerprint(publicKey)).toEqual(vector.fingerprint);
    expect(asJWK(publicKey)).toEqual(vector.publicKeyJwk);
    expect(fromJWK(asJWK(publicKey))).toEqual(publicKey);
  }
});

test("x25519", async () => {
  for (let vector of x25519) {
    const secret = u8a.fromString(vector.seed, "base16");
    const privateKey = keyFactory.fromSecret(AlgorithmKind.x25519, secret);
    const publicKey = await privateKey.publicKey();
    expect(fingerprint(publicKey)).toEqual(vector.fingerprint);
    expect(asJWK(publicKey)).toEqual(vector.publicKeyJwk);
    expect(fromJWK(asJWK(publicKey))).toEqual(publicKey);
  }
});
