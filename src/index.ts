import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  Relay,
  SimplePool,
  SubCloser,
  finalizeEvent,
  generateSecretKey,
  getPublicKey as nostrToolsGetPubkey,
  type Event as NostrEvent,
  type EventTemplate as NostrEventTemplate,
} from "nostr-tools";
import * as nip04 from "nostr-tools/nip04";
import { decode as decodeNip19 } from "nostr-tools/nip19";

export type NostrSigner = {
  getPublicKey(): Promise<string>;
  signEvent(event: NostrEventTemplate): Promise<NostrEvent>;
  nip04Encrypt(recipentPubkey: string, plaintext: string): Promise<string>;
  nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string>;
};

export class SecretKeySigner implements NostrSigner {
  #secKeyHex: string;
  #secKeyBytes: Uint8Array;

  public constructor(secKeyHex: string);
  public constructor(secKeyBytes: Uint8Array);
  public constructor(secKey: string | Uint8Array) {
    if (typeof secKey === "string") {
      this.#secKeyHex = secKey;
      this.#secKeyBytes = hexToBytes(secKey);
    } else {
      this.#secKeyBytes = secKey;
      this.#secKeyHex = bytesToHex(secKey);
    }
  }

  public static withRandomKey(): SecretKeySigner {
    return new SecretKeySigner(generateSecretKey());
  }

  public get secretKey(): string {
    return this.#secKeyHex;
  }

  public get publicKey(): string {
    return nostrToolsGetPubkey(this.#secKeyBytes);
  }

  public async getPublicKey(): Promise<string> {
    return this.publicKey;
  }

  public async signEvent(event: NostrEventTemplate): Promise<NostrEvent> {
    return Promise.resolve(finalizeEvent(event, this.#secKeyBytes));
  }

  public async nip04Encrypt(recipentPubkey: string, plaintext: string): Promise<string> {
    return nip04.encrypt(this.#secKeyHex, recipentPubkey, plaintext);
  }

  public async nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return nip04.decrypt(this.#secKeyHex, senderPubkey, ciphertext);
  }
}

export type Nip07Extension = {
  getPublicKey(): Promise<string>;
  signEvent(event: NostrEventTemplate): Promise<NostrEvent>;
  nip04?: {
    encrypt(pubKey: string, value: string): Promise<string>;
    decrypt(pubKey: string, value: string): Promise<string>;
  };
};

export class Nip07ExtensionSigner implements NostrSigner {
  #nip07Ext: Required<Nip07Extension>;

  public constructor(nip07Ext: Nip07Extension) {
    this.#nip07Ext = nip07Ext as Required<Nip07Extension>;
  }

  public async getPublicKey(): Promise<string> {
    return this.#nip07Ext.getPublicKey();
  }

  public async signEvent(event: NostrEventTemplate): Promise<NostrEvent> {
    return this.#nip07Ext.signEvent(event);
  }

  public async nip04Encrypt(recipentPubkey: string, plaintext: string): Promise<string> {
    return this.#nip07Ext.nip04.encrypt(recipentPubkey, plaintext);
  }

  public async nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return this.#nip07Ext.nip04.decrypt(senderPubkey, ciphertext);
  }
}

// cf. https://github.com/kind-0/nsecbunkerd/blob/master/src/config/index.ts#L29-L32
const defaultNip46Relays = ["wss://relay.nsecbunker.com", "wss://relay.damus.io"];

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
    in: [pubkey: string, secret?: string];
    out: string;
  };
  get_public_key: {
    in: [];
    out: string;
  };
  sign_event: {
    in: [event: NostrEventTemplate];
    out: NostrEvent;
  };
  nip04_encrypt: {
    in: [remotePubkey: string, plainText: string];
    out: string;
  };
  nip04_decrypt: {
    in: [remotePubkey: string, cipherText: string];
    out: string;
  };
};

type Nip46RpcMethods = keyof Nip46RpcSignatures;
type Nip46RpcParams<M extends Nip46RpcMethods> = Nip46RpcSignatures[M]["in"];
type Nip46RpcResult<M extends Nip46RpcMethods> = Nip46RpcSignatures[M]["out"];

type Nip46RpcParamsEncoders = {
  [K in keyof Nip46RpcSignatures]: (params: Nip46RpcParams<K>) => string[];
};
type Nip46RpcResultDecoders = {
  [K in keyof Nip46RpcSignatures]: (rawResult: string) => Nip46RpcResult<K>;
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

const parsePubkey = (pubkey: string): string | undefined => {
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
      const [secret, relays] = rest.split("?", 2) as [string, string];
      parts = { pubkey, secret, relays };
    } else {
      parts = { pubkey, secret: rest };
    }
  } else {
    if (token.includes("?")) {
      const qi = token.indexOf("?");
      const ri = token.indexOf("relay=");
      if (ri < qi) {
        throw Error("invalid connection token");
      }
      const [pubkey, relays] = token.split("?", 2) as [string, string];
      parts = { pubkey, relays };
    } else {
      parts = { pubkey: token };
    }
  }

  const pubkey = parsePubkey(parts.pubkey);
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

export class Nip46RemoteSigner implements NostrSigner {
  #localSigner: NostrSigner;
  #remotePubkey: string;

  #relayUrls: string[];
  #relayPool: SimplePool;
  #subCloser: SubCloser | undefined = undefined;

  #inflightRpcs: Map<string, Deferred<string>> = new Map();
  #opTimeoutMs: number;

  private constructor(
    localSigner: NostrSigner,
    remotePubkey: string,
    relayPool: SimplePool,
    relayUrls: string[],
    opTimeoutMs: number,
  ) {
    this.#localSigner = localSigner;
    this.#remotePubkey = remotePubkey;
    this.#relayPool = relayPool;
    this.#relayUrls = relayUrls;
    this.#opTimeoutMs = opTimeoutMs;
  }

  async #startSubscribeRpcResp() {
    const connResults = await Promise.allSettled(
      this.#relayUrls.map((rurl) => this.#relayPool.ensureRelay(rurl, { connectionTimeout: 5000 })),
    );
    const connectedRelays = connResults.reduce(
      (rs, r) => (r.status === "fulfilled" ? [...rs, r.value] : rs),
      [] as Relay[],
    );
    if (connectedRelays.length === 0) {
      throw Error("failed to connect to relays for NIP-46 RPC");
    }

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

    this.#subCloser = this.#relayPool.subscribeMany(this.#relayUrls, [{ kinds: [24133], "#p": [localPubkey] }], {
      onevent,
    });
  }

  #startListeningRpcResp(rpcId: string, timeoutMs: number): Deferred<string> {
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
    const respWaiter = this.#startListeningRpcResp(rpcId, timeoutMs);

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
    const signed = await this.#localSigner.signEvent(reqEv);
    this.#relayPool.publish(this.#relayUrls, signed);

    // rethrows if RPC result in error.
    const rawResp = await respWaiter.promise;
    return nip46RpcResultDecoders[method](rawResp);
  }

  public static async connect(
    localSigner: NostrSigner,
    connToken: string,
    operationTimeoutMs = 60 * 1000,
  ): Promise<Nip46RemoteSigner> {
    try {
      const connParams = parseNip46ConnectionToken(connToken);
      return Nip46RemoteSigner.connectWithParams(localSigner, connParams, operationTimeoutMs);
    } catch {
      throw Error("given NIP-46 connection token is invalid");
    }
  }

  private static async connectWithParams(
    localSigner: NostrSigner,
    { remotePubkey, secretToken, relayUrls }: Nip46ConnectionParams,
    operationTimeoutMs: number,
  ): Promise<Nip46RemoteSigner> {
    const relayPool = new SimplePool();
    const finalRelayUrls = relayUrls ? relayUrls : defaultNip46Relays;

    const signer = new Nip46RemoteSigner(localSigner, remotePubkey, relayPool, finalRelayUrls, operationTimeoutMs);
    await signer.#startSubscribeRpcResp();

    const localPubkey = await localSigner.getPublicKey();
    const connParams: [string] = [localPubkey];
    if (secretToken !== undefined) {
      connParams.push(secretToken);
    }

    try {
      const connResp = await signer.#requestNip46Rpc("connect", connParams, operationTimeoutMs);
      if (connResp !== "ack") {
        console.warn("NIP-46 remote signer responded for `connect` with other than 'ack'");
      }
      return signer;
    } catch (err) {
      // HACK: nsecBunker returns error if you connect twice to it with the same token. However, in spite of the error, other methods still work with the token.
      // It seems that Coracle just ignores this error on conenct, and we follow the behavior here.
      if (err instanceof Error && err.message.includes("Token already redeemed")) {
        console.log("ignoring 'Token already redeemed' error on connect");
        return signer;
      }
      throw err;
    }
  }

  public dispose() {
    this.#subCloser?.close();
  }

  public [Symbol.dispose]() {
    this.dispose();
  }

  public async getPublicKey(): Promise<string> {
    return this.#requestNip46Rpc("get_public_key", [], this.#opTimeoutMs);
  }

  public async signEvent(event: NostrEventTemplate): Promise<NostrEvent> {
    // HACK: set pubkey to event here, since sometimes nsecbunkerd fails to sign event if the input doesn't have pubkey field.
    const ev = event as NostrEventTemplate & { pubkey?: string };
    if (!ev.pubkey) {
      ev.pubkey = this.#remotePubkey;
    }
    return this.#requestNip46Rpc("sign_event", [ev], this.#opTimeoutMs);
  }

  public async nip04Encrypt(recipentPubkey: string, plaintext: string): Promise<string> {
    return this.#requestNip46Rpc("nip04_encrypt", [recipentPubkey, plaintext], this.#opTimeoutMs);
  }

  public async nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return this.#requestNip46Rpc("nip04_decrypt", [senderPubkey, ciphertext], this.#opTimeoutMs);
  }
}

const generateRpcId = () => Math.random().toString(32).substring(2, 8);

const currentUnixtimeSec = () => Math.floor(new Date().getTime() / 1000);
