# Keys

Un-opinionated public/private key representation for secp256k1 and ed25519 crypto systems.

## Install

Using [pnpm](https://pnpm.js.org):

```
pnpm add @silentcastle/keys
```

## Usage

Supported algorithms: secp256k1 and ed25519.

```ts
import { PrivateKeyFactory, AlgorithmKind } from '@silentcastle/keys';

// Get private key somehow. Here it is a managed instance.
const privateKeyFactory = new PrivateKeyFactory();
const privateKey = privateKeyFactory.fromSeed(AlgorithmKind.secp256k1, 'seed');
const publicKey = await privateKey.publicKey()

const message = new Uint8Array([1,2,3])
const signature = await privateKey.sign(new Uint8Array([1,2,3]))
const isSigned = await publicKey.verify(message, signature) // Expect true
```

## License

[MIT](https://opensource.org/licenses/MIT) or [Apache-2.0](https://opensource.org/licenses/Apache-2.0).
