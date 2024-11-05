import type { NostrEvent, EventTemplate as NostrEventTemplate } from "nostr-tools";
import { Deferred, currentUnixtimeSec, generateRandomString } from "../helpers";
import type { NostrSigner } from "../interface";
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

const parseRpcResp = async (ev: NostrEvent, signer: NostrSigner): Promise<Nip46RpcResp> => {
  const plainContent = await signer.nip04Decrypt(ev.pubkey, ev.content);
  return JSON.parse(plainContent) as Nip46RpcResp;
};

type Nip46RpcSignatures = {
  connect: {
    params: [pubkey: string, secret?: string, permissions?: string];
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
  nip44_encrypt: {
    params: [remotePubkey: string, plainText: string];
    result: string;
  };
  nip44_decrypt: {
    params: [remotePubkey: string, cipherText: string];
    result: string;
  };
  ping: {
    params: [];
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
  nip44_encrypt: identity,
  nip44_decrypt: identity,
  ping: identity,
};
const nip46RpcResultDecoders: Nip46RpcResultDecoders = {
  connect: identity,
  get_public_key: identity,
  sign_event: (raw: string) => JSON.parse(raw) as NostrEvent,
  nip04_encrypt: identity,
  nip04_decrypt: identity,
  nip44_encrypt: identity,
  nip44_decrypt: identity,
  ping: identity,
};

export class Nip46RpcClient {
  #localSigner: NostrSigner;
  #remotePubkey: string;

  #relayPool: RelayPool;
  #closeSub: (() => void) | undefined = undefined;

  #inflightRpcs: Map<string, Deferred<string>> = new Map();

  constructor(localSigner: NostrSigner, remotePubkey: string, relayPool: RelayPool) {
    this.#localSigner = localSigner;
    this.#remotePubkey = remotePubkey;
    this.#relayPool = relayPool;
  }

  /**
   * Start waiting for a `connect` response from a remote signer.
   */
  public static startWaitingForConnectRespFromRemote(
    localSigner: SecretKeySigner,
    relayPool: RelayPool,
    secret: string,
  ): { respReceived: Promise<string>; cancel: () => void } {
    const respReceived = new Deferred<string>();

    const onEvent = async (ev: NostrEvent) => {
      try {
        const resp = await parseRpcResp(ev, localSigner);
        if (resp.error) {
          respReceived.reject(new Error(`NIP-46 RPC resulted in error: ${resp.error}`));
          return;
        }
        if (!resp.result) {
          respReceived.reject(new Error("NIP-46 RPC: empty response"));
          return;
        }

        const signerPubkey = ev.pubkey;
        if (resp.result === "ack") {
          // TODO: approve "ack" for now, but should be rejected in the future
          console.warn("NIP-46 RPC: remote signer respondeds with just 'ack'");
          respReceived.resolve(signerPubkey);
          return;
        }

        if (resp.result !== secret) {
          respReceived.reject(new Error("NIP-46 RPC: secret mismatch"));
          return;
        }
        // secret returned from the remote siner matches with the one in connection token!
        respReceived.resolve(signerPubkey);
      } finally {
        closeListenSub();
      }
    };

    const ac = new AbortController();
    const cancel = () => ac.abort();

    const closeListenSub = relayPool.subscribe({ kinds: [24133], "#p": [localSigner.publicKey] }, onEvent);
    ac.signal.addEventListener(
      "abort",
      async () => {
        respReceived.reject(new Error("cancelled waiting for a connect response from a remote signer"));
        closeListenSub();
      },
      { once: true },
    );

    return { respReceived: respReceived.promise, cancel };
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
  ): Promise<Nip46RpcClient> {
    let rpcCli: Nip46RpcClient | undefined;
    try {
      rpcCli = new Nip46RpcClient(localSigner, remotePubkey, relayPool);
      await rpcCli.#startRespSubscription();
      return rpcCli;
    } catch (e) {
      rpcCli?.dispose();
      throw e;
    }
  }

  async #startRespSubscription() {
    const localPubkey = await this.#localSigner.getPublicKey();

    const onevent = async (ev: NostrEvent) => {
      let rpcId: string | undefined;
      try {
        const resp = await parseRpcResp(ev, this.#localSigner);
        rpcId = resp.id;

        const respWait = this.#inflightRpcs.get(resp.id);
        if (respWait === undefined) {
          console.debug("no waiter found for NIP-46 RPC response");
          return;
        }

        // there are cases that both `error` and `result` have values, so check error first
        if (resp.error) {
          respWait.reject(new Error(`NIP-46 RPC resulted in error: ${resp.error}`));
        } else if (resp.result) {
          respWait.resolve(resp.result);
        } else {
          respWait.reject(new Error("NIP-46 RPC: empty response"));
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
    timeoutMs: number,
  ): Promise<Nip46RpcResult<M>> {
    const rpcId = generateRandomString();
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
