import type { Filter, NostrEvent } from "nostr-tools";
import { type RxNostr, createRxForwardReq, createRxNostr, uniq } from "rx-nostr";
import { currentUnixtimeSec, delay } from "../helpers";

export type RelayPool = {
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

export class RxNostrRelayPool implements RelayPool {
  #rxn: RxNostr;
  #relayUrls: string[];

  constructor(relayUrls: string[]) {
    this.#relayUrls = relayUrls;

    const rxn = createRxNostr({ skipFetchNip11: true, connectionStrategy: "lazy-keep" });
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
        throw Error("failed to publish: timed out multiple times and max retry count exceeded");
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
