import type { Event as NostrEvent, EventTemplate as NostrEventTemplate } from "nostr-tools";
import { getPublicKey as getPubkeyFromHex } from "rx-nostr";
import { generateRandomString, mergeOptionsWithDefaults, parsePubkey } from "../helpers";
import type { NostrSigner, RelayList } from "../interface";
import { SecretKeySigner } from "../secret_key";
import { type RelayPool, RxNostrRelayPool } from "./relay_pool";
import { Nip46RpcClient, type Nip46RpcClientOptions, defaultRpcCliOptions } from "./rpc";

export type Nip46ConnectionParams = {
  remotePubkey: string;
  relayUrls: string[];
  secretToken?: string | undefined;
};

// parse connection token (format: bunker://<hex-pubkey>?relay=wss://...&relay=wss://...&secret=<optional-secret>)
export const parseConnToken = (token: string): Nip46ConnectionParams => parseUriConnToken(token);

const parseUriConnToken = (token: string): Nip46ConnectionParams => {
  let u: URL;
  try {
    u = new URL(token);
  } catch {
    throw Error("invalid connection token");
  }
  if (u.protocol !== "bunker:") {
    throw Error("invalid connection token");
  }

  const rawPubkey = u.host;
  const remotePubkey = parsePubkey(rawPubkey);
  if (remotePubkey === undefined) {
    throw Error("connection token contains invalid pubkey");
  }
  const secretToken = u.searchParams.get("secret") ?? undefined;
  const relayUrls = u.searchParams.getAll("relay");
  if (relayUrls.length === 0) {
    throw Error("connection token contains no relay URLs");
  }

  return {
    remotePubkey,
    relayUrls,
    secretToken,
  };
};

export type Nip46SessionState = Nip46ConnectionParams & {
  sessionKey: string;
};

type StartSessionResult = {
  /**
   * A handle for the connected NIP-46 remote signer.
   */
  signer: Nip46RemoteSigner;

  /**
   * State data needed to resume a session to the NIP-46 remote signer later.
   */
  session: Nip46SessionState;
};

export type Nip46ClientMetadata = {
  name: string;
  url?: string;
  description?: string;
  icons?: string[];
};

export type Nip46RemoteSignerOptions = Nip46RpcClientOptions;

export type Nip46RemoteSignerConnectOptions = Nip46RemoteSignerOptions & {
  /**
   * The maximum amount of time allowed to attempt to connect to a remote signer, in milliseconds.
   *
   * @default 30000
   */
  connectTimeoutMs?: number;

  /**
   * The permissions to request on the connection.
   */
  permissions?: string[];
};

const defaultConnectOptions: Required<Nip46RemoteSignerConnectOptions> = {
  ...defaultRpcCliOptions,
  connectTimeoutMs: 30 * 1000,
  permissions: [],
};

/**
 * An implementation of NostrSigner based on a [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) remote signer (a.k.a. Nostr Connect or nsecBunker).
 * It acts as a client-side handle for a NIP-46 remote signer.
 *
 * You can initialize a Nip46RemoteSigner instance by calling one of the following initialization methods, each corresponds to a signer discovery flow defined in NIP-46:
 *
 * - `Nip46RemoteSigner.connectToRemote(connToken)`: "Started by the signer (nsecBunker)" discovery flow
 * - `Nip46RemoteSigner.listenConnectionFromRemote(relayUrls, clientMetadata)`: "Started by the client" discovery flow
 *
 * During an initialization process, a session to a remote signer is established. Session state data is returned as a result of the initialization, along with a Nip46RemoteSigner instance.
 * Your app should store the session state data, and use it to resume the session later via `Nip46RemoteSigner.resumeSession(sessionState)`.
 */
export class Nip46RemoteSigner implements NostrSigner, Disposable {
  #rpcCli: Nip46RpcClient;
  #remotePubkey: string;

  private constructor(rpcCli: Nip46RpcClient, remotePubkey: string) {
    this.#rpcCli = rpcCli;
    this.#remotePubkey = remotePubkey;
  }

  /**
   * Creates a NIP-46 remote signer handle with RPC response subscription started.
   *
   * It's guaranteed that the signer handle and its internal relay pool are disposed in case of an initialization error.
   */
  static async #init(
    localSigner: NostrSigner,
    remotePubkey: string,
    relayUrls: string[],
    options: Required<Nip46RemoteSignerOptions>,
  ): Promise<Nip46RemoteSigner> {
    let relayPool: RelayPool | undefined;
    try {
      relayPool = new RxNostrRelayPool(relayUrls);
    } catch (e) {
      relayPool?.dispose();
      throw e;
    }

    const rpcCli = await Nip46RpcClient.init(localSigner, remotePubkey, relayPool, options);
    return new Nip46RemoteSigner(rpcCli, remotePubkey);
  }

  /**
   * Initializes a NIP-46 remote signer handle, then performs a connection handshake.
   *
   * It's guaranteed that the signer handle and its internal relay pool are disposed in case of a connection handshake error.
   */
  static async #connect(
    localSigner: NostrSigner,
    { remotePubkey, secretToken, relayUrls }: Nip46ConnectionParams,
    options: Required<Nip46RemoteSignerConnectOptions>,
  ): Promise<Nip46RemoteSigner> {
    const signer = await Nip46RemoteSigner.#init(localSigner, remotePubkey, relayUrls, options);

    // perform connection handshake
    try {
      const connParams: [string] = [remotePubkey];
      if (secretToken !== undefined) {
        connParams.push(secretToken);
      }
      if (options.permissions.length > 0) {
        connParams.push(options.permissions.join(","));
      }

      const connResp = await signer.#rpcCli.request("connect", connParams, options.connectTimeoutMs);
      if (connResp !== "ack") {
        console.warn("NIP-46 remote signer responded for `connect` with other than 'ack'");
      }
      return signer;
    } catch (err) {
      // HACK: nsecBunker returns error if you connect twice to it with the same token. However, in spite of the error, other methods still work with the token.
      // It seems that Coracle just ignores this error on connect, and we follow the behavior here.
      if (err instanceof Error && err.message.includes("Token already redeemed")) {
        console.debug("ignoring 'Token already redeemed' error on connect from remote signer");
        return signer;
      }

      signer.dispose();
      throw err;
    }
  }

  /**
   * Connects to a NIP-46 remote signer with a given connection token, and establishes a session to the remote signer.
   * This is the "Started by the signer (nsecBunker)" signer discovery flow defined in NIP-46.
   *
   * Internally, it generates SecretKeySigner with a random secret key and use it to communicate with a remote signer.
   * This secret key acts as a "session key", and it is returned along with other session data (as `session` property).
   * You should store the session state data (`session`) in somewhere to resume the session later via `Nip46RemoteSigner.resumeSession`.
   *
   * @returns a Promise that resolves to an object that contains a handle for the connected remote signer and a session state
   */
  public static async connectToRemote(
    connToken: string,
    options: Nip46RemoteSignerConnectOptions = {},
  ): Promise<StartSessionResult> {
    const finalOpts = mergeOptionsWithDefaults(defaultConnectOptions, options);

    const connParams = parseConnToken(connToken);
    const localSigner = SecretKeySigner.withRandomKey();
    const sessionKey = localSigner.secretKey;

    return {
      signer: await Nip46RemoteSigner.#connect(localSigner, connParams, finalOpts),
      session: {
        sessionKey,
        ...connParams,
      },
    };
  }

  /**
   * Starts to listen a connection request from a NIP-46 remote signer, and once a connection request is received, establishes a session to the remote signer.
   * This is the "Started by the client" signer discovery flow defined in NIP-46.
   *
   * Internally, it generates SecretKeySigner with a random secret key and use it to communicate with a remote signer.
   * This secret key acts as a "session key", and it is returned along with other session data (as `session` property).
   * You should store the session state data (`session`) in somewhere to resume the session later via `Nip46RemoteSigner.resumeSession`.
   *
   * @returns an object with following properties:
   *  - `connectUri`: a URI that can be shared with the remote signer to connect to this client
   *  - `established`: a Promise that resolves to an object that contains a handle for the connected remote signer and a session state
   */
  public static listenConnectionFromRemote(
    relayUrls: string[],
    clientMetadata: Nip46ClientMetadata,
    options: Nip46RemoteSignerConnectOptions = {},
  ): {
    connectUri: string;
    established: Promise<StartSessionResult>;
  } {
    const finalOpts = mergeOptionsWithDefaults(defaultConnectOptions, options);

    const localSigner = SecretKeySigner.withRandomKey();
    const sessionKey = localSigner.secretKey;
    const localPubkey = getPubkeyFromHex(sessionKey);

    // construct nostrconnect URI
    const connSecret = generateRandomString();
    const connUri = new URL(`nostrconnect://${localPubkey}`);
    for (const rurl of relayUrls) {
      connUri.searchParams.append("relay", rurl);
    }
    const metaWithPerms = {
      ...clientMetadata,
      perms: finalOpts.permissions.length > 0 ? finalOpts.permissions.join(",") : undefined,
    };
    connUri.searchParams.set("metadata", JSON.stringify(metaWithPerms));
    connUri.searchParams.set("secret", connSecret);

    // start listening for `connect` response from the remote signer
    const relayPool = new RxNostrRelayPool(relayUrls);

    const { connected } = Nip46RpcClient.startWaitingForConnectRespFromRemote(
      localSigner,
      relayPool,
      connSecret,
      finalOpts.connectTimeoutMs,
    );

    // once `connect` response is received, initialize a handle for the remote signer
    const established = connected.then(async (remotePubkey): Promise<StartSessionResult> => {
      const rpcCli = await Nip46RpcClient.init(localSigner, remotePubkey, relayPool, finalOpts);
      const signer = new Nip46RemoteSigner(rpcCli, remotePubkey);
      return {
        signer,
        session: {
          sessionKey,
          remotePubkey,
          relayUrls,
        },
      };
    });

    return {
      connectUri: connUri.toString(),
      established,
    };
  }

  /**
   * Resumes a session to a NIP-46 remote signer, which is established by `Nip46RemoteSigner.connectToRemote` or `Nip46RemoteSigner.listenConnectionFromRemote`.
   */
  public static async resumeSession(
    { sessionKey, ...connParams }: Nip46SessionState,
    options: Nip46RemoteSignerOptions = {},
  ): Promise<Nip46RemoteSigner> {
    const finalOpts = mergeOptionsWithDefaults(defaultRpcCliOptions, options);

    const localSigner = new SecretKeySigner(sessionKey);
    return Nip46RemoteSigner.#init(localSigner, connParams.remotePubkey, connParams.relayUrls, finalOpts);
  }

  /**
   * Returns the public key that corresponds to the underlying secret key, in hex string format.
   */
  public async getPublicKey(): Promise<string> {
    return this.#rpcCli.request("get_public_key", []);
  }

  /**
   * Returns the list of relays preferred by the user.
   *
   * Each entry is a mapping from the relay URL to the preferred use (read/write) of the relay.
   */
  public async getRelays(): Promise<RelayList> {
    return this.#rpcCli.request("get_relays", []);
  }

  /**
   * Signs a given Nostr event with the underlying secret key.
   *
   * @param event a Nostr event template (unsigned event)
   * @returns a Promise that resolves to a signed Nostr event
   */
  public async signEvent(event: NostrEventTemplate): Promise<NostrEvent> {
    // HACK: set pubkey to event here, since sometimes nsecbunkerd fails to sign event if the input doesn't have pubkey field.
    const ev = event as NostrEventTemplate & { pubkey?: string };
    if (!ev.pubkey) {
      ev.pubkey = this.#remotePubkey;
    }
    return this.#rpcCli.request("sign_event", [ev]);
  }

  /**
   * Encrypts a given text to secretly communicate with others, by the encryption algorithm defined in [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md).
   *
   * @param recipientPubkey a public key of a message recipient, in hex string format
   * @param plaintext a plaintext to encrypt
   * @returns a Promise that resolves to a encrypted text
   */
  public async nip04Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    return this.#rpcCli.request("nip04_encrypt", [recipientPubkey, plaintext]);
  }

  /**
   * Decrypts a given ciphertext from others, by the decryption algorithm defined in [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md).
   *
   * @param senderPubkey a public key of a message sender, in hex string format
   * @param ciphertext a ciphertext to decrypt
   * @returns a Promise that resolves to a decrypted text
   */
  public async nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return this.#rpcCli.request("nip04_decrypt", [senderPubkey, ciphertext]);
  }

  /**
   * Encrypts a given text to secretly communicate with others, by the encryption algorithm defined in [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md).
   *
   * @param recipientPubkey a public key of a message recipient, in hex string format
   * @param plaintext a plaintext to encrypt
   * @returns a Promise that resolves to a encrypted text
   */
  public async nip44Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    return this.#rpcCli.request("nip44_encrypt", [recipientPubkey, plaintext]);
  }

  /**
   * Decrypts a given ciphertext from others, by the decryption algorithm defined in [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md).
   *
   * @param senderPubkey a public key of a message sender, in hex string format
   * @param ciphertext a ciphertext to decrypt
   * @returns a Promise that resolves to a decrypted text
   */
  public async nip44Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return this.#rpcCli.request("nip44_decrypt", [senderPubkey, ciphertext]);
  }

  /**
   * Sends a ping to the remote signer.
   */
  public async ping(): Promise<void> {
    const resp = await this.#rpcCli.request("ping", []);
    // response should be "pong"
    if (resp !== "pong") {
      throw Error("unexpected response for ping from the remote signer");
    }
  }

  /**
   * Tries to reconnect to all the relays that are used to communicate with the remote signer.
   */
  public reconnectToRpcRelays() {
    this.#rpcCli.reconnectToRelays();
  }

  /**
   * Disposes this remote signer handle.
   */
  public dispose() {
    this.#rpcCli.dispose();
  }

  /**
   * Disposes this remote signer handle.
   */
  public [Symbol.dispose]() {
    this.dispose();
  }
}
