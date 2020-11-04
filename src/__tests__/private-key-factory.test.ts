import { PrivateKeyFactory } from "../private-key.factory";
import { KeyKind } from "../key-kind";

const privateKeyFactory = new PrivateKeyFactory();
const bytesSeed = new Uint8Array([1, 2, 3]);
const stringSeed = "hello";

describe("secp256k1", () => {
  test("generate from bytes", () => {
    const privateKey = privateKeyFactory.fromSeed(KeyKind.es256k, bytesSeed);
    expect(privateKey.kind).toEqual(KeyKind.es256k);
    expect(privateKey).toMatchSnapshot()
  });
  test("generate from string", () => {
    const privateKey = privateKeyFactory.fromSeed(KeyKind.es256k, stringSeed);
    expect(privateKey.kind).toEqual(KeyKind.es256k);
    expect(privateKey).toMatchSnapshot()
  });
});

describe("ed25519", () => {
  test("generate from bytes", () => {
    const privateKey = privateKeyFactory.fromSeed(KeyKind.ed25519, bytesSeed);
    expect(privateKey.kind).toEqual(KeyKind.ed25519);
    expect(privateKey).toMatchSnapshot()
  });
  test("generate from string", () => {
    const privateKey = privateKeyFactory.fromSeed(KeyKind.ed25519, stringSeed);
    expect(privateKey.kind).toEqual(KeyKind.ed25519);
    expect(privateKey).toMatchSnapshot()
  });
});
