# nostr-signer-connector
A library that allows Nostr clients to interact with various *Nostr event signers* in [a uniform manner](#the-nostrsigner-interface).

Currently this library supports 3 types of Nostr event signers:

- Signers based on a bare secret key (`SecretKeySigner`)
- [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) browser extensions (`Nip07ExtensionSigner`)
- [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) remote signer a.k.a. Nostr Connect / [nsecBunker](https://nsecbunker.com/) (`Nip46RemoteSigner`)
    + Both "Started by the signer (nsecBunker)" and "Started by the client" signer discovery flows are supported!

With this, you can support "Login with nsecBunker" feature in your Nostr app without relying on [NDK](https://github.com/nostr-dev-kit/ndk)! If you curious about it, [read `Nip46RemoteSigner` usage](#nip46remotesigner).

## Installation
```
npm install nostr-signer-connector
```

## Usage: How to Initialize Signer Instances
### `SecretKeySigner`
Signers based on a bare secret key on memory.

You can create it from a secret (private) key in various format using the constructor:
- Hex string
- Bech32-encoded key (`nsec1...`)
- 32 bytes of binary data (in a `Uint8Array`)

```ts
import { SecretKeySigner } from 'nostr-signer-connector';

// from hex string
const hexkey = "deadbeef...";
const signer1 = new SecretKeySigner(hexkey);

// from nsec
const nsec = "nsec1...";
const signer2 = new SecretKeySigner(nsec);

// from binary
const binkey: Uint8Array = ...;
const signer3 = new SecretKeySigner(binkey);
```

### `Nip07ExtensionSigner`
Signers based on a [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) browser extension.

You can create it by passing a `window.nostr` instance to the constructor.

```ts
import { Nip07ExtensionSigner, type Nip07Extension } from 'nostr-signer-connector';

const signer = new Nip07ExtensionSigner(window.nostr as Nip07Extension);
```

### `Nip46RemoteSigner`
Signers based on a [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) remote signer (a.k.a. Nostr Connect or nsecBunker).

You **can't** create `Nip46RemoteSigner` instances using the constructor.
You should use static initialization methods on `Nip46RemoteSigner` class, appropriate for type of remote signer you want to support.

#### Connect to a nsecBunker ("Started by the signer" flow)
**Use `Nip46RemoteSigner.connectToRemote()`**.

It tries to connect to a nsecBunker by passing the connection token (`npub1...#<secret>?relay=<relay-url>`) generated by a remote signer (nsecBunker), and establishes a session to the nsecBunker.

If it succeeded to connect, the returned promise resolves to an object that have session data (`session`) along with a handle to the nsecBunker (`signer`).
**You should store this session data in somewhere** to resume the session later (e.g. after a browser reload).

```ts
import { Nip46RemoteSigner } from 'nostr-signer-connector';

const connToken = "npub1...#secret-token?relay=wss%3A%2F%2Frelay.nsecbunker.com"
const { signer, session } = await Nip46RemoteSigner.connectToRemote(connToken);

// store session data to LocalStorage
localStorage.setItem("nostr_connect_session", JSON.stringify(session));

// use the signer as you want...
const ev = await signer.signEvent({...});
```

#### Listen connection from a remote signer ("Started by the client" flow)
**Use `Nip46RemoteSigner.listenConnectionFromRemote()`**.

It starts to listen a connection request from a remote signer, and establishes a session to the remote signer once a connection request is received.

First of all, it gererates a connect URI (`nostrconnect://...`) which allows a remote signer to send connect request to your app.
You should show the URI to users in some way, and instruct them to paste it on their remote signer.

You can wait until a session is established by `await`-ing on `established` property in the return value.
This promise resolves to an object that have session data (`session`) along with a handle to the nsecBunker (`signer`).
**You should store this session data in somewhere** to resume the session later (e.g. after a browser reload).

You can cancel listening a connection from remote signer by calling `cancel` function in the return value.
When you cancel, `established` is rejected with an error.

```ts
import { Nip46RemoteSigner, type Nip46ClientMetadata } from 'nostr-signer-connector';

const relayUrls = ["wss://relay.damus.io"];
const client: Nip46ClientMetadata = {
    name: "sample client",
    url: "https://example.com",
    description: "just a sample"
};
const { connectUri, established, cancel } = 
    Nip46RemoteSigner.listenConnectionFromRemote(relayUrls, client);

// show the connect URI to user
console.log("paste this URI on Nostr Connect signer:", connectUri);

// wait until a session to a remote signer is established...
const { signer, session } = await established;

// store session data to LocalStorage
localStorage.setItem("nostr_connect_session", JSON.stringify(session));

// use the signer as you want...
const ev = await signer.signEvent({...});
```

#### Resume a session to a remote signer
Once a session to a remote signer have been established by initialization methods above,
you can resume the session by passing a stored session data to **`Nip46RemoteSigner.resumeSession()`**.

```ts
import { Nip46RemoteSigner, type Nip46SessionState } from 'nostr-signer-connector';

const rawSess = localStorage.getItem("nostr_connect_session")
if (rawSess === null) {
    // session not stored: start session by methods above
}

const sess = JSON.parse(rawSess) as Nip46SessionState;
const signer = await Nip46RemoteSigner.resumeSession(sess);

// use the signer as you want...
const ev = await signer.signEvent({...});
```

## The `NostrSigner` Interface
All signer implementations share common interface as follows:

```ts
/**
 * The common interface of Nostr event signer.
 */
type NostrSigner = {
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
