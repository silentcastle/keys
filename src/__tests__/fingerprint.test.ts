import { PrivateKeyFactory } from "../private-key.factory";
import { AlgorithmKind } from "../algorithm-kind";
import { fingerprint } from "../fingerprint";

const factory = new PrivateKeyFactory();

test("secp256k1", async () => {
  const privateKey = factory.fromSeed(AlgorithmKind.secp256k1, "seed");
  const publicKey = await privateKey.publicKey();
  expect(fingerprint(publicKey)).toMatchSnapshot();
});

test("ed25519", async () => {
  const privateKey = factory.fromSeed(AlgorithmKind.ed25519, "seed");
  const publicKey = await privateKey.publicKey();
  expect(fingerprint(publicKey)).toMatchSnapshot();
});

test("x25519", async () => {
  const privateKey = factory.fromSeed(AlgorithmKind.x25519, "seed");
  const publicKey = await privateKey.publicKey();
  expect(fingerprint(publicKey)).toMatchSnapshot();
});
