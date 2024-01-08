import { type Filter, type Event as NostrEvent, type EventTemplate as NostrEventTemplate } from "nostr-tools";
import { decode as decodeNip19 } from "nostr-tools/nip19";
import { RxNostr, createRxForwardReq, createRxNostr, uniq } from "rx-nostr";
import type { NostrSigner } from "./interface";
import { SecretKeySigner } from "./secret_key";

const currentUnixtimeSec = () => Math.floor(Date.now() / 1000);

interface Deferred<T> {
  resolve(v: T | PromiseLike<T>): void;
  reject(e?: unknown): void;
}

// eslint-disable-next-line @typescript-eslint/no-unsafe-declaration-merging
class Deferred<T> {
  promise: Promise<T>;
  constructor() {
    this.promise = new Promise((resolve, reject) => {
      this.resolve = (v) => {
        resolve(v);
      };
      this.reject = (e) => {
        reject(e);
      };
    });
  }
}

type RelayPool = {
  // starts to subscribe events
  subscribe(filter: Filter, onEvent: (ev: NostrEvent) => void): () => void;
  // publishes a Nostr event
  publish(ev: NostrEvent): void;
  // try to reconnect to all relays
  reconnectAll(): void;
};

class RxNostrRelayPool implements RelayPool {
  #rxn: RxNostr;
  #relayUrls: string[];

  constructor(relayUrls: string[]) {
    this.#relayUrls = relayUrls;

    const rxn = createRxNostr({ skipFetchNip11: true });
    rxn.setDefaultRelays(relayUrls);

    rxn.createConnectionStateObservable().subscribe(({ from: rurl, state }) => {
      console.log(`[Nip46RemoteSigner] ${rurl}: connection state changed to ${state}`);
    });

    this.#rxn = rxn;
  }

  subscribe(filter: Filter, onEvent: (ev: NostrEvent) => void): () => void {
    const req = createRxForwardReq();
    const sub = this.#rxn
      .use(req)
      .pipe(uniq())
      .subscribe(({ event }) => onEvent(event));

    req.emit({ ...filter, since: currentUnixtimeSec });
    return () => sub.unsubscribe();
  }

  publish(ev: NostrEvent): void {
    this.#rxn.send(ev);
  }

  reconnectAll(): void {
    this.#relayUrls.map((rurl) => {
      this.#rxn.reconnect(rurl);
    });
  }
}

type Nip46RpcReq = {
  id: string;
  method: string;
  params: string[];
};

type Nip46RpcResp = {
  id: string;
  result?: string;
  error?: string;
};

type Nip46RpcSignatures = {
  connect: {
    params: [pubkey: string, secret?: string];
    result: string;
  };
  get_public_key: {
    params: [];
    result: string;
  };
  sign_event: {
    params: [event: NostrEventTemplate];
    result: NostrEvent;
  };
  nip04_encrypt: {
    params: [remotePubkey: string, plainText: string];
    result: string;
  };
  nip04_decrypt: {
    params: [remotePubkey: string, cipherText: string];
    result: string;
  };
};

type Nip46RpcMethods = keyof Nip46RpcSignatures;
type Nip46RpcParams<M extends Nip46RpcMethods> = Nip46RpcSignatures[M]["params"];
type Nip46RpcResult<M extends Nip46RpcMethods> = Nip46RpcSignatures[M]["result"];

type Nip46RpcParamsEncoders = {
  [M in keyof Nip46RpcSignatures]: (params: Nip46RpcParams<M>) => string[];
};
type Nip46RpcResultDecoders = {
  [M in keyof Nip46RpcSignatures]: (rawResult: string) => Nip46RpcResult<M>;
};

const identity = <T>(v: T) => v;
const nip46RpcParamsEncoders: Nip46RpcParamsEncoders = {
  connect: (params) => params as string[],
  get_public_key: identity,
  sign_event: ([ev]) => [JSON.stringify(ev)],
  nip04_encrypt: identity,
  nip04_decrypt: identity,
};
const nip46RpcResultDecoders: Nip46RpcResultDecoders = {
  connect: identity,
  get_public_key: identity,
  sign_event: (raw: string) => JSON.parse(raw) as NostrEvent,
  nip04_encrypt: identity,
  nip04_decrypt: identity,
};

type Nip46ConnectionParams = {
  remotePubkey: string;
  secretToken?: string | undefined;
  relayUrls?: string[] | undefined;
};

const decodePubkey = (pubkey: string): string | undefined => {
  if (pubkey.startsWith("npub1")) {
    return decodeNip19(pubkey as `npub1${string}`).data;
  }
  if (/[0-9a-f]{64}/.test(pubkey)) {
    return pubkey;
  }
  return undefined;
};

const parseNip46ConnectionToken = (token: string): Nip46ConnectionParams => {
  let parts: {
    pubkey: string;
    secret?: string;
    relays?: string;
  };

  if (token.includes("#")) {
    const [pubkey, rest] = token.split("#", 2) as [string, string];
    if (token.includes("?")) {
      const qi = token.indexOf("?");
      const ri = token.indexOf("relay=");
      if (ri < qi) {
        throw Error("invalid connection token");
      }
      // <pubkey>#<secret>?<relays>
      const [secret, relays] = rest.split("?", 2) as [string, string];
      parts = { pubkey, secret, relays };
    } else {
      // <pubkey>#<secret>
      parts = { pubkey, secret: rest };
    }
  } else {
    if (token.includes("?")) {
      const qi = token.indexOf("?");
      const ri = token.indexOf("relay=");
      if (ri < qi) {
        throw Error("invalid connection token");
      }
      // <pubkey>?<relays>
      const [pubkey, relays] = token.split("?", 2) as [string, string];
      parts = { pubkey, relays };
    } else {
      // <pubkey>
      parts = { pubkey: token };
    }
  }

  const pubkey = decodePubkey(parts.pubkey);
  if (pubkey === undefined) {
    throw Error("connection token contains invalid pubkey");
  }

  const relayUrls = parts.relays?.replace("relay=", "").split("&relay=");
  try {
    relayUrls?.forEach((r) => new URL(r));
  } catch {
    throw Error("connection token contains invalid relay URL");
  }

  return {
    remotePubkey: pubkey,
    secretToken: parts.secret,
    relayUrls,
  };
};

const generateRpcId = () => Math.random().toString(32).substring(2, 8);

// Default relays used by nsecbunkerd
// cf. https://github.com/kind-0/nsecbunkerd/blob/master/src/config/index.ts#L29-L32
const defaultNip46Relays = ["wss://relay.nsecbunker.com", "wss://relay.damus.io"];

/**
 * An implementaion of NostrSigner based on a [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) remote signer (a.k.a. Nostr Connect or nsecBunker).
 */
export class Nip46RemoteSigner implements NostrSigner, Disposable {
  #localSigner: NostrSigner;
  #remotePubkey: string;

  #relayPool: RelayPool;
  #closeSub: (() => void) | undefined = undefined;

  #inflightRpcs: Map<string, Deferred<string>> = new Map();
  #opTimeoutMs: number;

  private constructor(localSigner: NostrSigner, remotePubkey: string, relayPool: RelayPool, opTimeoutMs: number) {
    this.#localSigner = localSigner;
    this.#remotePubkey = remotePubkey;
    this.#relayPool = relayPool;
    this.#opTimeoutMs = opTimeoutMs;
  }

  async #startRpcRespSubscription() {
    const localPubkey = await this.#localSigner.getPublicKey();

    const onevent = async (ev: NostrEvent) => {
      let rpcId: string | undefined;
      try {
        const plainContent = await this.#localSigner.nip04Decrypt(this.#remotePubkey, ev.content);
        const resp = JSON.parse(plainContent) as Nip46RpcResp;
        rpcId = resp.id;

        const respWait = this.#inflightRpcs.get(resp.id);
        if (respWait === undefined) {
          console.debug("no waiter found for NIP-46 RPC response");
          return;
        }

        if (resp.error !== undefined) {
          respWait.reject(new Error(`NIP-46 RPC resulted in error: ${resp.error}`));
        } else {
          if (resp.result) {
            respWait.resolve(resp.result);
          } else {
            respWait.reject(new Error(`NIP-46 RPC: empty response`));
          }
        }
      } catch (err) {
        console.error("error on receiving NIP-46 RPC response", err);
      }

      if (rpcId !== undefined) {
        this.#inflightRpcs.delete(rpcId);
      }
    };
    this.#closeSub = this.#relayPool.subscribe({ kinds: [24133], "#p": [localPubkey] }, onevent);
  }

  #startWaitingRpcResp(rpcId: string, timeoutMs: number): Deferred<string> {
    const d = new Deferred<string>();
    this.#inflightRpcs.set(rpcId, d);

    const signal = AbortSignal.timeout(timeoutMs);
    signal.addEventListener(
      "abort",
      () => {
        d.reject(new Error("NIP-46 RPC timed out!"));
        this.#inflightRpcs.delete(rpcId);
      },
      { once: true },
    );
    return d;
  }

  async #requestNip46Rpc<M extends Nip46RpcMethods>(
    method: M,
    params: Nip46RpcParams<M>,
    timeoutMs: number,
  ): Promise<Nip46RpcResult<M>> {
    const rpcId = generateRpcId();
    const respWaiter = this.#startWaitingRpcResp(rpcId, timeoutMs);

    const rpcReq: Nip46RpcReq = {
      id: rpcId,
      method,
      params: nip46RpcParamsEncoders[method](params),
    };
    const cipheredReq = await this.#localSigner.nip04Encrypt(this.#remotePubkey, JSON.stringify(rpcReq));
    const reqEv: NostrEventTemplate = {
      kind: 24133,
      tags: [["p", this.#remotePubkey]],
      content: cipheredReq,
      created_at: currentUnixtimeSec(),
    };
    const signedReqEv = await this.#localSigner.signEvent(reqEv);
    this.#relayPool.publish(signedReqEv);

    // rethrows if RPC result in error.
    const rawResp = await respWaiter.promise;
    return nip46RpcResultDecoders[method](rawResp);
  }

  /**
   * Connects to a NIP-46 remote signer with raw connection parameters.
   */
  public static async connectWithParams(
    localSigner: NostrSigner,
    { remotePubkey, secretToken, relayUrls }: Nip46ConnectionParams,
    operationTimeoutMs: number,
  ): Promise<Nip46RemoteSigner> {
    const finalRelayUrls = relayUrls ? relayUrls : defaultNip46Relays;
    const relayPool = new RxNostrRelayPool(finalRelayUrls);

    const signer = new Nip46RemoteSigner(localSigner, remotePubkey, relayPool, operationTimeoutMs);
    await signer.#startRpcRespSubscription();

    // perform connection handshake
    try {
      const localPubkey = await localSigner.getPublicKey();
      const connParams: [string] = [localPubkey];
      if (secretToken !== undefined) {
        connParams.push(secretToken);
      }

      const connResp = await signer.#requestNip46Rpc("connect", connParams, operationTimeoutMs);
      if (connResp !== "ack") {
        console.warn("NIP-46 remote signer responded for `connect` with other than 'ack'");
      }
      return signer;
    } catch (err) {
      // HACK: nsecBunker returns error if you connect twice to it with the same token. However, in spite of the error, other methods still work with the token.
      // It seems that Coracle just ignores this error on conenct, and we follow the behavior here.
      if (err instanceof Error && err.message.includes("Token already redeemed")) {
        console.log("ignoring 'Token already redeemed' error on connect from remote signer");
        return signer;
      }
      throw err;
    }
  }

  /**
   * Connects to a NIP-46 remote signer with connection token and returns a handle for the remote signer if succeeds.
   *
   * The NostrSigner given as `localSigner` is used for encrypting a RPC request payload, sigining a RPC request event (kind: 24133) and decrypting a RPC response payload.
   *
   * If the given connection token doesn't have relays part, default relays used by nsecbunkerd are used for RPC communications.
   */
  public static async connect(
    localSigner: NostrSigner,
    connToken: string,
    operationTimeoutMs = 15 * 1000,
  ): Promise<Nip46RemoteSigner> {
    try {
      const connParams = parseNip46ConnectionToken(connToken);
      return Nip46RemoteSigner.connectWithParams(localSigner, connParams, operationTimeoutMs);
    } catch {
      throw Error("given NIP-46 connection token is invalid");
    }
  }

  /**
   * Starts a "session" to a NIP-46 remote signer.
   *
   * Internally, it connects to a NIP-46 remote signer whose `localSigner` is a SecretKeySigner with a random secret key.
   * The secret key in the `localSigner` acts as a "session key", and it is returned along with a handle for the remote signer.
   */
  public static async startSession(
    connToken: string,
    operationTimeoutMs = 15 * 1000,
  ): Promise<{
    sessionKey: string;
    signer: Nip46RemoteSigner;
  }> {
    const localSigner = SecretKeySigner.withRandomKey();
    const sessionKey = localSigner.secretKey;

    return {
      sessionKey,
      signer: await Nip46RemoteSigner.connect(localSigner, connToken, operationTimeoutMs),
    };
  }

  /**
   * Resumes a "session" to a NIP-46 remote signer.
   *
   * Internally, it connects to a NIP-46 remote signer whose `localSigner` is a SecretKeySigner with the given session key.
   */
  public static async resumeSession(
    sessionKey: string,
    connToken: string,
    operationTimeoutMs = 15 * 1000,
  ): Promise<Nip46RemoteSigner> {
    const localSigner = new SecretKeySigner(sessionKey);
    return Nip46RemoteSigner.connect(localSigner, connToken, operationTimeoutMs);
  }

  /**
   * Returns the public key that corresponds to the underlying secret key, in hex string format.
   */
  public async getPublicKey(): Promise<string> {
    return this.#requestNip46Rpc("get_public_key", [], this.#opTimeoutMs);
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
    return this.#requestNip46Rpc("sign_event", [ev], this.#opTimeoutMs);
  }

  /**
   * Encrypts a given text to secretly communicate with others, by the encryption algorithm defined in [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md).
   *
   * @param recipentPubkey a public key of a message recipent, in hex string format
   * @param plaintext a plaintext to encrypt
   * @returns a Promise that resolves to a encrypted text
   */
  public async nip04Encrypt(recipentPubkey: string, plaintext: string): Promise<string> {
    return this.#requestNip46Rpc("nip04_encrypt", [recipentPubkey, plaintext], this.#opTimeoutMs);
  }

  /**
   * Decrypts a given ciphertext from others, by the decryption algorithm defined in [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md).
   *
   * @param senderPubkey a public key of a message sender, in hex string format
   * @param ciphertext a ciphertext to decrypt
   * @returns a Promise that resolves to a decrypted text
   */
  public async nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return this.#requestNip46Rpc("nip04_decrypt", [senderPubkey, ciphertext], this.#opTimeoutMs);
  }

  /**
   * Tries to reconnect to all the relays that are used to communicate with the remote signer.
   */
  public reconnectToRpcRelays() {
    this.#relayPool.reconnectAll();
  }

  public dispose() {
    if (this.#closeSub !== undefined) {
      this.#closeSub?.();
      this.#closeSub = undefined;
    }
    this.#inflightRpcs.clear();
  }

  public [Symbol.dispose]() {
    this.dispose();
  }
}
