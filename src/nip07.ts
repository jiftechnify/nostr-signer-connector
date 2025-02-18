import type { Event as NostrEvent, EventTemplate as NostrEventTemplate } from "nostr-tools";
import { Deferred, mergeOptionsWithDefaults } from "./helpers";
import type { NostrSigner, RelayList } from "./interface";

export type Nip07Extension = {
  getPublicKey(): Promise<string>;
  signEvent(event: NostrEventTemplate): Promise<NostrEvent>;
  getRelays?(): Promise<RelayList>;
  nip04?: {
    encrypt?(pubKey: string, value: string): Promise<string>;
    decrypt?(pubKey: string, value: string): Promise<string>;
  };
  nip44?: {
    encrypt?(pubKey: string, value: string): Promise<string>;
    decrypt?(pubKey: string, value: string): Promise<string>;
  };
};

export type Nip07ExtensionSignerOptions = {
  /**
   * Enables the request queueing.
   * Under the request queueing, you can still call methods concurrently, though actually only a single request is executed at a point in time.
   *
   * This is useful when the NIP-07 extension you use can't process concurrent requests correctly.
   *
   * @default false
   */
  enableQueueing?: boolean;
};

const defaultOptions: Required<Nip07ExtensionSignerOptions> = {
  enableQueueing: false,
};

/**
 * An implementation of NostrSigner based on a [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) browser extension.
 *
 * NOTE: `nip04/nip44`-`Encrypt/Decrypt` methods throw error if the underlying NIP-07 extension doesn't support them.
 */
export class Nip07ExtensionSigner implements NostrSigner {
  #nip07Ext: Nip07Extension;
  #reqSerializer: RequestSerializer;

  /**
   * Creates a Nip07ExtensionSigner from an instance of NIP-07 browser extension.
   *
   * @param nip07Ext an instance of NIP-07 extension (`window.nostr`)
   */
  public constructor(nip07Ext: Nip07Extension, options: Nip07ExtensionSignerOptions = {}) {
    this.#nip07Ext = nip07Ext;

    const { enableQueueing } = mergeOptionsWithDefaults(defaultOptions, options);
    if (enableQueueing) {
      this.#reqSerializer = new ReqSerializationQueue();
    } else {
      this.#reqSerializer = new NoopReqSerializer();
    }
  }

  /**
   * Returns the public key that corresponds to the underlying secret key, in hex string format.
   */
  public async getPublicKey(): Promise<string> {
    return this.#reqSerializer.addRequest(() => this.#nip07Ext.getPublicKey());
  }

  /**
   * Returns the list of relays preferred by the user.
   *
   * Each entry is a mapping from the relay URL to the preferred use (read/write) of the relay.
   */
  public async getRelays(): Promise<RelayList> {
    if (typeof this.#nip07Ext.getRelays !== "function") {
      throw Error("NIP-07 browser extension doesn't support getRelays");
    }
    // biome-ignore lint/style/noNonNullAssertion: extension's field existence hardly changes during runtime
    return this.#reqSerializer.addRequest(() => this.#nip07Ext.getRelays!());
  }

  /**
   * Signs a given Nostr event with the underlying secret key.
   *
   * @param event a Nostr event template (unsigned event)
   * @returns a Promise that resolves to a signed Nostr event
   */
  public async signEvent(event: NostrEventTemplate): Promise<NostrEvent> {
    return this.#reqSerializer.addRequest(() => this.#nip07Ext.signEvent(event));
  }

  /**
   * Encrypts a given text to secretly communicate with others, by the encryption algorithm defined in [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md).
   *
   * @param recipientPubkey a public key of a message recipient, in hex string format
   * @param plaintext a plaintext to encrypt
   * @returns a Promise that resolves to a encrypted text
   */
  public async nip04Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    if (typeof this.#nip07Ext.nip04?.encrypt !== "function") {
      throw Error("NIP-07 browser extension doesn't support nip04.encrypt");
    }
    // biome-ignore lint/style/noNonNullAssertion: extension's field existence hardly changes during runtime
    return this.#reqSerializer.addRequest(() => this.#nip07Ext.nip04!.encrypt!(recipientPubkey, plaintext));
  }

  /**
   * Decrypts a given ciphertext from others, by the decryption algorithm defined in [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md).
   *
   * @param senderPubkey a public key of a message sender, in hex string format
   * @param ciphertext a ciphertext to decrypt
   * @returns a Promise that resolves to a decrypted text
   */
  public async nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    if (typeof this.#nip07Ext.nip04?.decrypt !== "function") {
      throw Error("NIP-07 browser extension doesn't support nip04.decrypt");
    }
    // biome-ignore lint/style/noNonNullAssertion: extension's field existence hardly changes during runtime
    return this.#reqSerializer.addRequest(() => this.#nip07Ext.nip04!.decrypt!(senderPubkey, ciphertext));
  }

  /**
   * Encrypts a given text to secretly communicate with others, by the encryption algorithm defined in [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md).
   *
   * @param recipientPubkey a public key of a message recipient, in hex string format
   * @param plaintext a plaintext to encrypt
   * @returns a Promise that resolves to a encrypted text
   */
  public async nip44Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    if (typeof this.#nip07Ext.nip44?.encrypt !== "function") {
      throw Error("NIP-07 browser extension doesn't support nip44.encrypt");
    }
    // biome-ignore lint/style/noNonNullAssertion: extension's field existence hardly changes during runtime
    return this.#reqSerializer.addRequest(() => this.#nip07Ext.nip44!.encrypt!(recipientPubkey, plaintext));
  }

  /**
   * Decrypts a given ciphertext from others, by the decryption algorithm defined in [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md).
   *
   * @param senderPubkey a public key of a message sender, in hex string format
   * @param ciphertext a ciphertext to decrypt
   * @returns a Promise that resolves to a decrypted text
   */
  public async nip44Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    if (typeof this.#nip07Ext.nip44?.decrypt !== "function") {
      throw Error("NIP-07 browser extension doesn't support nip44.decrypt");
    }
    // biome-ignore lint/style/noNonNullAssertion: extension's field existence hardly changes during runtime
    return this.#reqSerializer.addRequest(() => this.#nip07Ext.nip44!.decrypt!(senderPubkey, ciphertext));
  }
}

interface RequestSerializer {
  addRequest<T>(req: () => Promise<T>): Promise<T>;
}

class ReqSerializationQueue implements RequestSerializer {
  #reqQ: (() => Promise<unknown>)[] = [];
  #running = false;

  public addRequest<T>(req: () => Promise<T>): Promise<T> {
    const d = new Deferred<T>();
    const r = async () => {
      try {
        d.resolve(await req());
      } catch (err) {
        d.reject(err);
      }
    };
    this.#reqQ.push(r);

    if (!this.#running) {
      this.#running = true;
      this.startLoop();
    }

    return d.promise;
  }

  private async startLoop() {
    try {
      while (true) {
        const req = this.#reqQ.shift();
        if (req === undefined) {
          break;
        }
        await req();
      }
    } finally {
      this.#running = false;
    }
  }
}

class NoopReqSerializer implements RequestSerializer {
  public addRequest<T>(req: () => Promise<T>): Promise<T> {
    return req();
  }
}
