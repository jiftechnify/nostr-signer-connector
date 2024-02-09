import { setTimeout as delay } from "node:timers/promises";
import { type Filter, type Event as NostrEvent, type EventTemplate as NostrEventTemplate } from "nostr-tools";
import { RxNostr, createRxForwardReq, createRxNostr, getPublicKey as getPubkeyFromHex, uniq } from "rx-nostr";
import { parsePubkey } from "./helpers";
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
  // start to subscribe events
  subscribe(filter: Filter, onEvent: (ev: NostrEvent) => void): () => void;
  // try to publish a Nostr event and wait for at least one OK response
  publish(ev: NostrEvent): Promise<void>;
  // try to reconnect to all relays
  reconnectAll(): void;
  // dispose the relay pool
  dispose(): void;
};

type TryPubResult =
  | {
      status: "ok";
    }
  | {
      status: "timeout";
    }
  | {
      status: "error";
      reason: string;
    };

class RxNostrRelayPool implements RelayPool {
  #rxn: RxNostr;
  #relayUrls: string[];

  constructor(relayUrls: string[]) {
    this.#relayUrls = relayUrls;

    const rxn = createRxNostr({ skipFetchNip11: true });
    rxn.setDefaultRelays(relayUrls);

    rxn.createConnectionStateObservable().subscribe(({ from: rurl, state }) => {
      console.debug(`[Nip46RemoteSigner] ${rurl}: connection state changed to ${state}`);
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

  async publish(ev: NostrEvent): Promise<void> {
    const maxRetry = 3;
    let retry = 0;

    while (true) {
      if (retry === maxRetry) {
        throw Error(`failed to publish: timed out multiple times and max retry count exceeded`);
      }
      const res = await this.#tryPub(ev, 3000);
      switch (res.status) {
        case "ok":
          return;

        case "error":
          throw Error(`failed to publish event: ${res.reason}`);

        case "timeout":
          await delay((1 << retry) * 1000);
          retry++;
      }
    }
  }

  // try to publish event, and wait for at least one OK response
  async #tryPub(ev: NostrEvent, timeoutMs: number): Promise<TryPubResult> {
    return new Promise<TryPubResult>((resolve) => {
      try {
        const timeoutSig = AbortSignal.timeout(timeoutMs);
        timeoutSig.addEventListener("abort", () => {
          okSub.unsubscribe();
          resolve({ status: "timeout" });
        });
        const okSub = this.#rxn.send(ev).subscribe(({ ok, notice }) => {
          if (ok) {
            resolve({ status: "ok" });
          } else {
            resolve({ status: "error", reason: notice ?? "(empty reason)" });
          }
        });
      } catch (err) {
        if (err instanceof Error) {
          resolve({ status: "error", reason: err.message });
        } else {
          resolve({ status: "error", reason: "(unknown error)" });
        }
      }
    });
  }

  reconnectAll(): void {
    this.#relayUrls.map((rurl) => {
      this.#rxn.reconnect(rurl);
    });
  }

  dispose(): void {
    this.#rxn.dispose();
  }
}

type Nip46RpcReq = {
  id: string;
  method: string;
  params: string[];
};

type Nip46RpcResp = {
  id: string;
  result?: string | undefined | null;
  error?: string | undefined | null;
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

export type Nip46ConnectionParams = {
  remotePubkey: string;
  secretToken?: string | undefined;
  relayUrls: string[];
};

const parseConnToken = (token: string): Nip46ConnectionParams => {
  const isUriFormat = token.startsWith("bunker://");
  return isUriFormat ? parseUriConnToken(token) : parseLegacyConnToken(token);
};

// parse connection token (new URI format: bunker://<hex-pubkey>?relay=wss://...&relay=wss://...&secret=<optional-secret>)
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

  return {
    remotePubkey,
    secretToken,
    relayUrls,
  };
};

// parse connection token (legacy format: <nsec1...>#<secret>?relay=wss://...&relay=wss://...)
const parseLegacyConnToken = (token: string): Nip46ConnectionParams => {
  let parts: {
    pubkey: string;
    secret?: string;
    relays?: string;
  };

  const splitRelaysPart = (s: string): [string, string] => {
    const qi = s.indexOf("?");
    const ri = s.indexOf("relay=");
    if (ri < qi) {
      throw Error("invalid connection token");
    }
    return s.split("?", 2) as [string, string];
  };

  if (token.includes("#")) {
    const [pubkey, rest] = token.split("#", 2) as [string, string];
    if (rest.includes("?")) {
      // <pubkey>#<secret>?<relays>
      const [secret, relays] = splitRelaysPart(rest);
      parts = { pubkey, secret, relays };
    } else {
      // <pubkey>#<secret>
      parts = { pubkey, secret: rest };
    }
  } else {
    if (token.includes("?")) {
      // <pubkey>?<relays>
      const [pubkey, relays] = splitRelaysPart(token);
      parts = { pubkey, relays };
    } else {
      // <pubkey>
      parts = { pubkey: token };
    }
  }

  const pubkey = parsePubkey(parts.pubkey);
  if (pubkey === undefined) {
    throw Error("connection token contains invalid pubkey");
  }

  const relayUrls =
    parts.relays
      ?.replace("relay=", "")
      .split("&relay=")
      .map((r) => decodeURIComponent(r)) ?? [];
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

export type Nip46ClientMetadata = { name: string; url?: string; description?: string; icons?: string[] };

const generateRpcId = () => Math.random().toString(32).substring(2, 8);

// Default relays used by nsecbunkerd
// cf. https://github.com/kind-0/nsecbunkerd/blob/master/src/config/index.ts#L29-L32
const defaultNip46Relays = ["wss://relay.nsecbunker.com", "wss://relay.damus.io"];

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
  #localSigner: NostrSigner;
  #remotePubkey: string;

  #relayPool: RelayPool;
  #closeRpcSub: (() => void) | undefined = undefined;

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

        // there are cases that `error` and `result` both have values, so check error first
        if (resp.error) {
          respWait.reject(new Error(`NIP-46 RPC resulted in error: ${resp.error}`));
        } else if (resp.result) {
          respWait.resolve(resp.result);
        } else {
          respWait.reject(new Error(`NIP-46 RPC: empty response`));
        }
      } catch (err) {
        console.error("error on receiving NIP-46 RPC response", err);
      }

      if (rpcId !== undefined) {
        this.#inflightRpcs.delete(rpcId);
      }
    };
    this.#closeRpcSub = this.#relayPool.subscribe({ kinds: [24133], "#p": [localPubkey] }, onevent);
  }

  #startWaitingRpcResp(rpcId: string): { waitResp: Promise<string>; startCancelTimer: (timeoutMs: number) => void } {
    const d = new Deferred<string>();
    this.#inflightRpcs.set(rpcId, d);

    const startCancelTimer = (timeoutMs: number) => {
      const signal = AbortSignal.timeout(timeoutMs);
      signal.addEventListener(
        "abort",
        () => {
          d.reject(new Error("NIP-46 RPC timed out!"));
          this.#inflightRpcs.delete(rpcId);
        },
        { once: true },
      );
    };

    return { waitResp: d.promise, startCancelTimer };
  }

  async #requestNip46Rpc<M extends Nip46RpcMethods>(
    method: M,
    params: Nip46RpcParams<M>,
    timeoutMs: number,
  ): Promise<Nip46RpcResult<M>> {
    const rpcId = generateRpcId();
    const { waitResp, startCancelTimer } = this.#startWaitingRpcResp(rpcId);

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

    await this.#relayPool.publish(signedReqEv);

    // once the request is sent, start a timer to cancel the request if it takes too long
    startCancelTimer(timeoutMs);

    // rethrow if RPC result in error.
    const rawResp = await waitResp;
    return nip46RpcResultDecoders[method](rawResp);
  }

  /**
   * Creates a NIP-46 remote signer handle with RPC response subscription started.
   *
   * It's guaranteed that the signer handle and its internal relay pool are disposed in case of an initialization error.
   */
  static async #init(
    localSigner: NostrSigner,
    remotePubkey: string,
    relayUrls: string[] | undefined,
    operationTimeoutMs: number,
  ): Promise<Nip46RemoteSigner> {
    const relayUrlsOrDefault = relayUrls ? relayUrls : defaultNip46Relays;

    let relayPool: RelayPool | undefined;
    try {
      relayPool = new RxNostrRelayPool(relayUrlsOrDefault);
    } catch (e) {
      relayPool?.dispose();
      throw e;
    }

    let signer: Nip46RemoteSigner | undefined;
    try {
      signer = new Nip46RemoteSigner(localSigner, remotePubkey, relayPool, operationTimeoutMs);
      signer.#startRpcRespSubscription();
      return signer;
    } catch (e) {
      signer?.dispose();
      throw e;
    }
  }

  /**
   * Initializes a NIP-46 remote signer handle, then performs a connection handshake.
   *
   * It's guaranteed that the signer handle and its internal relay pool are disposed in case of a connection handshake error.
   */
  static async #connect(
    localSigner: NostrSigner,
    { remotePubkey, secretToken, relayUrls }: Nip46ConnectionParams,
    operationTimeoutMs: number,
  ): Promise<Nip46RemoteSigner> {
    const signer = await Nip46RemoteSigner.#init(localSigner, remotePubkey, relayUrls, operationTimeoutMs);

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
  public static async connectToRemote(connToken: string, operationTimeoutMs = 15 * 1000): Promise<StartSessionResult> {
    const connParams = parseConnToken(connToken);
    const localSigner = SecretKeySigner.withRandomKey();
    const sessionKey = localSigner.secretKey;

    return {
      signer: await Nip46RemoteSigner.#connect(localSigner, connParams, operationTimeoutMs),
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
   *  - `cancel`: a function that cancels listening connection from a remote signer
   */
  public static listenConnectionFromRemote(
    relayUrls: string[],
    clientMetadata: Nip46ClientMetadata,
    operationTimeoutMs = 15 * 1000,
  ): {
    connectUri: string;
    established: Promise<StartSessionResult>;
    cancel: () => void;
  } {
    const localSigner = SecretKeySigner.withRandomKey();
    const sessionKey = localSigner.secretKey;
    const localPubkey = getPubkeyFromHex(sessionKey);

    // construct nostrconnect URI
    const connUri = new URL(`nostrconnect://${localPubkey}`);
    for (const rurl of relayUrls) {
      connUri.searchParams.append("relay", rurl);
    }
    connUri.searchParams.append("metadata", JSON.stringify(clientMetadata));

    const ac = new AbortController();
    const cancel = () => ac.abort();

    // a promise that is resolved once a 'connect' request from a remote signer is received
    const established = new Promise<StartSessionResult>((resolve, reject) => {
      const relayPool = new RxNostrRelayPool(relayUrls);

      const onevent = async (ev: NostrEvent) => {
        try {
          const signerPubkey = ev.pubkey;
          const plainContent = await localSigner.nip04Decrypt(signerPubkey, ev.content);
          const req = JSON.parse(plainContent) as Nip46RpcReq;
          if (req.method !== "connect") {
            console.warn("ignoring request other than 'connect'");
            return;
          }
          if (req.params.length <= 0) {
            console.warn("ignoring 'connect' request with empty params");
            return;
          }
          const paramPubkey = parsePubkey(req.params[0] as string);
          if (paramPubkey === undefined || signerPubkey !== paramPubkey) {
            console.warn("ignoring 'connect' request with invalid pubkey");
            return;
          }

          const resp: Nip46RpcResp = {
            id: req.id,
            result: "ack",
            error: "",
          };
          const cipheredResp = await localSigner.nip04Encrypt(signerPubkey, JSON.stringify(resp));
          const respEv: NostrEventTemplate = {
            kind: 24133,
            tags: [["p", signerPubkey]],
            content: cipheredResp,
            created_at: currentUnixtimeSec(),
          };
          const signedResp = await localSigner.signEvent(respEv);

          await relayPool.publish(signedResp);

          // session established!
          // close subscription for listening 'connect' from remote
          closeListenSub();

          // create a signer handle and start subscription for RPC resp
          const signer = new Nip46RemoteSigner(localSigner, signerPubkey, relayPool, operationTimeoutMs);
          signer.#startRpcRespSubscription();
          resolve({
            signer,
            session: {
              sessionKey,
              remotePubkey: signerPubkey,
              relayUrls,
            },
          });
        } catch (err) {
          console.error("error on accepting connect request from remote signer", err);
        }
      };

      // start to listen connect request
      const closeListenSub = relayPool.subscribe({ kinds: [24133], "#p": [localPubkey] }, onevent);

      // cancel listening connection
      ac.signal.addEventListener(
        "abort",
        async () => {
          reject(Error("Nip46RemoteSigner.listenConnection: canceled"));
          closeListenSub();
        },
        { once: true },
      );
    });

    return {
      connectUri: connUri.toString(),
      established,
      cancel,
    };
  }

  /**
   * Resumes a session to a NIP-46 remote signer, which is established by `Nip46RemoteSigner.connectToRemote` or `Nip46RemoteSigner.listenConnectionFromRemote`.
   */
  public static async resumeSession(
    { sessionKey, ...connParams }: Nip46SessionState,
    operationTimeoutMs = 15 * 1000,
  ): Promise<Nip46RemoteSigner> {
    const localSigner = new SecretKeySigner(sessionKey);
    return Nip46RemoteSigner.#init(localSigner, connParams.remotePubkey, connParams.relayUrls, operationTimeoutMs);
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
   * @param recipientPubkey a public key of a message recipient, in hex string format
   * @param plaintext a plaintext to encrypt
   * @returns a Promise that resolves to a encrypted text
   */
  public async nip04Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    return this.#requestNip46Rpc("nip04_encrypt", [recipientPubkey, plaintext], this.#opTimeoutMs);
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

  /**
   * Disposes this remote signer handle.
   */
  public dispose() {
    if (this.#closeRpcSub !== undefined) {
      this.#closeRpcSub?.();
      this.#closeRpcSub = undefined;
    }
    this.#relayPool.dispose();
    this.#inflightRpcs.clear();
  }

  /**
   * Disposes this remote signer handle.
   */
  public [Symbol.dispose]() {
    this.dispose();
  }
}
