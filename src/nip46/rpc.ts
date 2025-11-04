import type { NostrEvent, EventTemplate as NostrEventTemplate } from "nostr-tools";
import { Deferred, currentUnixtimeSec, generateRandomString, mergeOptionsWithDefaults } from "../helpers";
import type { NostrSigner, RelayList } from "../interface";
import type { SecretKeySigner } from "../secret_key";
import type { RelayPool } from "./relay_pool";

export type Nip46RpcReq = {
  id: string;
  method: string;
  params: string[];
};

export type Nip46RpcResp = {
  id: string;
  result?: string | undefined | null;
  error?: string | undefined | null;
};

type ParsedNip46RpcResp = { id: string } & (
  | {
      status: "ok";
      result: string;
    }
  | {
      status: "error";
      error: string;
    }
  | {
      status: "auth";
      authUrl: string;
    }
  | {
      status: "empty";
    }
);

const parseNip46RpcResp = async (ev: NostrEvent, signer: NostrSigner): Promise<ParsedNip46RpcResp> => {
  const plainContent = await signer.nip44Decrypt(ev.pubkey, ev.content);
  const { id, result, error } = JSON.parse(plainContent) as Nip46RpcResp;

  // there are cases that both `error` and `result` have values, so check error first
  if (error != null) {
    // if `result` is "auth_url", response should be regarded as an auth challenge.
    // in this case, `error` points to a URL for user authentication.
    if (result === "auth_url") {
      return { id, status: "auth", authUrl: error };
    }
    return { id, status: "error", error };
  }
  if (result != null) {
    return { id, status: "ok", result };
  }
  return { id, status: "empty" };
};

type Nip46RpcSignatures = {
  connect: {
    params: [remotePubkey: string, secret?: string, permissions?: string];
    result: string;
  };
  sign_event: {
    params: [event: NostrEventTemplate];
    result: NostrEvent;
  };
  ping: {
    params: [];
    result: string;
  };
  get_relays: {
    params: [];
    result: RelayList;
  };
  get_public_key: {
    params: [];
    result: string;
  };
  nip04_encrypt: {
    params: [remotePubkey: string, plainText: string];
    result: string;
  };
  nip04_decrypt: {
    params: [remotePubkey: string, cipherText: string];
    result: string;
  };
  nip44_encrypt: {
    params: [remotePubkey: string, plainText: string];
    result: string;
  };
  nip44_decrypt: {
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
  sign_event: ([ev]) => [JSON.stringify(ev)],
  ping: identity,
  get_relays: identity,
  get_public_key: identity,
  nip04_encrypt: identity,
  nip04_decrypt: identity,
  nip44_encrypt: identity,
  nip44_decrypt: identity,
};
const nip46RpcResultDecoders: Nip46RpcResultDecoders = {
  connect: identity,
  sign_event: (raw: string) => JSON.parse(raw) as NostrEvent,
  ping: identity,
  get_relays: (raw: string) => JSON.parse(raw) as RelayList,
  get_public_key: identity,
  nip04_encrypt: identity,
  nip04_decrypt: identity,
  nip44_encrypt: identity,
  nip44_decrypt: identity,
};

export type Nip46RpcClientOptions = {
  /**
   * The maximum amount of time to wait for a response to a signer operation request, in milliseconds.
   *
   * @default 15000
   */
  requestTimeoutMs?: number;

  /**
   * The handler for auth challenge from a remote signer.
   *
   * Default is just ignoring any auth challenges.
   */
  onAuthChallenge?: (authUrl: string) => void;
};

export const defaultRpcCliOptions: Required<Nip46RpcClientOptions> = {
  requestTimeoutMs: 15 * 1000,
  onAuthChallenge: (_) => {
    console.debug("NIP-46 RPC: ignoring auth challenge...");
  },
};

export class Nip46RpcClient {
  #localSigner: NostrSigner;
  #remotePubkey: string;
  #options: Required<Nip46RpcClientOptions>;

  #relayPool: RelayPool;
  #closeSub: (() => void) | undefined = undefined;

  #inflightRpcs: Map<string, Deferred<string>> = new Map();

  constructor(
    localSigner: NostrSigner,
    remotePubkey: string,
    relayPool: RelayPool,
    options: Required<Nip46RpcClientOptions>,
  ) {
    this.#localSigner = localSigner;
    this.#remotePubkey = remotePubkey;
    this.#options = options;
    this.#relayPool = relayPool;
  }

  /**
   * Start waiting for a `connect` response from a remote signer.
   */
  public static startWaitingForConnectRespFromRemote(
    localSigner: SecretKeySigner,
    relayPool: RelayPool,
    secret: string,
    timeoutMs: number,
  ): { connected: Promise<string> } {
    const respWait = new Deferred<string>();

    const onEvent = async (ev: NostrEvent) => {
      const resp = await parseNip46RpcResp(ev, localSigner);
      switch (resp.status) {
        case "ok": {
          const signerPubkey = ev.pubkey;
          if (resp.result === "ack") {
            // TODO: approve "ack" for now, but should be rejected in the future
            console.warn("NIP-46 RPC: remote signer respondeds with just 'ack'");
            respWait.resolve(signerPubkey);
            return;
          }
          if (resp.result !== secret) {
            respWait.reject(new Error("NIP-46 RPC: secret mismatch"));
            return;
          }
          // secret returned from the remote siner matches with the one in connection token!
          respWait.resolve(signerPubkey);
          return;
        }
        case "auth":
          console.debug("NIP-46 RPC: ignoring auth challenge during waiting for connection from remote...");
          return;
        case "error":
          respWait.reject(new Error(`NIP-46 RPC resulted in error: ${resp.error}`));
          return;
        case "empty":
          respWait.reject(new Error("NIP-46 RPC: empty response"));
          return;
      }
    };

    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const onTimeout = async () => {
      respWait.reject(new Error("NIP-46: nostrconnect connection initiation flow timed out!"));
    };
    timeoutSignal.addEventListener("abort", onTimeout, { once: true });

    const unsub = relayPool.subscribe({ kinds: [24133], "#p": [localSigner.publicKey] }, onEvent);

    // cleanups to be performed on the settlement of `respWait`.
    const cleanup = () => {
      unsub();
      timeoutSignal.removeEventListener("abort", onTimeout);
    };
    return { connected: respWait.promise.finally(cleanup) };
  }

  /**
   * Creates a NIP-46 remote signer handle with RPC response subscription started.
   *
   * It's guaranteed that the signer handle and its internal relay pool are disposed in case of an initialization error.
   */
  public static async init(
    localSigner: NostrSigner,
    remotePubkey: string,
    relayPool: RelayPool,
    options: Nip46RpcClientOptions,
  ): Promise<Nip46RpcClient> {
    const finalOpts = mergeOptionsWithDefaults(defaultRpcCliOptions, options);

    let rpcCli: Nip46RpcClient | undefined;
    try {
      rpcCli = new Nip46RpcClient(localSigner, remotePubkey, relayPool, finalOpts);
      await rpcCli.#startRespSubscription();
      return rpcCli;
    } catch (e) {
      rpcCli?.dispose();
      throw e;
    }
  }

  async #startRespSubscription() {
    const onevent = async (ev: NostrEvent) => {
      let rpcId: string | undefined;
      try {
        const resp = await parseNip46RpcResp(ev, this.#localSigner);
        rpcId = resp.id;

        const respWait = this.#inflightRpcs.get(resp.id);
        if (respWait === undefined) {
          console.debug("no waiter found for NIP-46 RPC response");
          return;
        }

        switch (resp.status) {
          case "ok":
            respWait.resolve(resp.result);
            return;
          case "auth":
            this.#options.onAuthChallenge(resp.authUrl);
            return;
          case "error":
            respWait.reject(new Error(`NIP-46 RPC resulted in error: ${resp.error}`));
            return;
          case "empty":
            respWait.reject(new Error("NIP-46 RPC: empty response"));
            return;
        }
      } catch (err) {
        console.error("error on receiving NIP-46 RPC response", err);
      }

      if (rpcId !== undefined) {
        this.#inflightRpcs.delete(rpcId);
      }
    };

    const localPubkey = await this.#localSigner.getPublicKey();
    this.#closeSub = this.#relayPool.subscribe({ kinds: [24133], "#p": [localPubkey] }, onevent);
  }

  #startWaitingRpcResp(rpcId: string): {
    waitResp: Promise<string>;
    startCancelTimer: (timeoutMs: number) => void;
  } {
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

  public async request<M extends Nip46RpcMethods>(
    method: M,
    params: Nip46RpcParams<M>,
    timeoutMs = this.#options.requestTimeoutMs,
  ): Promise<Nip46RpcResult<M>> {
    const rpcId = generateRandomString();
    const { waitResp, startCancelTimer } = this.#startWaitingRpcResp(rpcId);

    const rpcReq: Nip46RpcReq = {
      id: rpcId,
      method,
      params: nip46RpcParamsEncoders[method](params),
    };
    const cipheredReq = await this.#localSigner.nip44Encrypt(this.#remotePubkey, JSON.stringify(rpcReq));
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
   * Tries to reconnect to all the relays that are used to communicate with the remote signer.
   */
  public reconnectToRelays() {
    this.#relayPool.reconnectAll();
  }

  /**
   * Disposes this remote signer handle.
   */
  public dispose() {
    if (this.#closeSub !== undefined) {
      this.#closeSub?.();
      this.#closeSub = undefined;
    }
    this.#relayPool.dispose();
    this.#inflightRpcs.clear();
  }
}
