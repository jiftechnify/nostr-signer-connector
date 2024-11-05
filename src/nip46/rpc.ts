import type { NostrEvent, EventTemplate as NostrEventTemplate } from "nostr-tools";
import { Deferred, currentUnixtimeSec } from "../helpers";
import type { NostrSigner } from "../interface";
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

const generateRpcId = () => Math.random().toString(32).substring(2, 8);

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

  public async request<M extends Nip46RpcMethods>(
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
