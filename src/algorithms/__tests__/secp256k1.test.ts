import * as secp256k1 from "../secp256k1";
import * as _ from "lodash";
import { AlgorithmKind } from "../../algorithm-kind";

const material = new Uint8Array(_.times(32, () => 1));
const key = new secp256k1.PrivateKey(material);
const message = new Uint8Array(_.times(32, (n) => n));

describe("PublicKey", () => {
  test("properties", () => {
    const material = new Uint8Array(_.times(32, () => 1));
    const publicKey = new secp256k1.PublicKey(material);
    expect(publicKey.kind).toEqual(AlgorithmKind.secp256k1);
    expect(publicKey.material).toEqual(material);
  });

  test("verify", async () => {
    const publicKey = await key.publicKey();
    const signature = await key.sign(message);
    await expect(publicKey.verify(message, signature)).resolves.toBeTruthy();
    await expect(
      publicKey.verify(message, new Uint8Array())
    ).resolves.toBeFalsy();
    await expect(
      publicKey.verify(new Uint8Array(), signature)
    ).resolves.toBeFalsy();
    const wrongPublicKey = new secp256k1.PublicKey(new Uint8Array());
    await expect(
      wrongPublicKey.verify(message, signature)
    ).resolves.toBeFalsy();
  });
});

describe("PrivateKey", () => {
  test("fields", async () => {
    expect(key.kind).toEqual(AlgorithmKind.secp256k1);
    const publicKey = await key.publicKey();
    expect(publicKey).toMatchSnapshot();
  });
  test("sign", async () => {
    const signature = await key.sign(material);
    expect(signature).toMatchSnapshot();
  });
});
