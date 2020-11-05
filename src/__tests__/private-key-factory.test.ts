import { PrivateKeyFactory } from "../private-key.factory";
import { AlgorithmKind } from "../algorithm-kind";

const privateKeyFactory = new PrivateKeyFactory();
const bytesSeed = new Uint8Array([1, 2, 3]);
const stringSeed = "hello";

describe("secp256k1", () => {
  test("generate from bytes", () => {
    const privateKey = privateKeyFactory.fromSeed(AlgorithmKind.secp256k1, bytesSeed);
    expect(privateKey.kind).toEqual(AlgorithmKind.secp256k1);
    expect(privateKey).toMatchSnapshot()
  });
  test("generate from string", () => {
    const privateKey = privateKeyFactory.fromSeed(AlgorithmKind.secp256k1, stringSeed);
    expect(privateKey.kind).toEqual(AlgorithmKind.secp256k1);
    expect(privateKey).toMatchSnapshot()
  });
});

describe("ed25519", () => {
  test("generate from bytes", () => {
    const privateKey = privateKeyFactory.fromSeed(AlgorithmKind.ed25519, bytesSeed);
    expect(privateKey.kind).toEqual(AlgorithmKind.ed25519);
    expect(privateKey).toMatchSnapshot()
  });
  test("generate from string", () => {
    const privateKey = privateKeyFactory.fromSeed(AlgorithmKind.ed25519, stringSeed);
    expect(privateKey.kind).toEqual(AlgorithmKind.ed25519);
    expect(privateKey).toMatchSnapshot()
  });
});
