# nostr-signer-connector
A library that allows Nostr clients to interact with various *Nostr event signers* in a uniform manner:

```ts
/**
 * The common interface of Nostr event signer.
 */
export type NostrSigner = {
  /**
   * Returns the public key that corresponds to the underlying secret key, in hex string format.
   */
  getPublicKey(): Promise<string>;

  /**
   * Signs a given Nostr event with the underlying secret key.
   */
  signEvent(event: NostrEventTemplate): Promise<NostrEvent>;

  /**
   * Encrypts a given text to secretly communicate with others, by the encryption algorithm defined in NIP-04.
   */
  nip04Encrypt(recipientPubkey: string, plaintext: string): Promise<string>;

  /**
   * Decrypts a given ciphertext from others, by the decryption algorithm defined in NIP-04.
   */
  nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string>;
};

```

Currently this library supports 3 types of Nostr event signers:

- Signers based on a bare secret key (`SecretKeySigner`)
- [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) browser extensions (`Nip07ExtensionSigner`)
- [NIP-46](https://github.com/nostr-protocol/nips/blob/master/07.md) remote signer a.k.a. Nostr Connect / [nsecBunker](https://nsecbunker.com/) (`Nip46RemoteSigner`)

## Installation
```
npm install nostr-signer-connector
```

## Establishing a Session to a NIP-46 Remote Signer

1. First time: start a session to a remote signer with `startSession`. A random *session key* will be created, and **clients should store it somewhere to resume the session later**.

```ts
const { sessionKey, signer } = await Nip46RemoteSigner.startSession(connectionToken);
```

2. Later, resume the session with `resumeSession`, passing a stored *session key*.

```ts
const signer = await Nip46RemoteSigner.resumeSession(sessionKey, connectionToken);
```
