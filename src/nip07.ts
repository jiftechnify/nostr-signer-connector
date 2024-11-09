import type { Event as NostrEvent, EventTemplate as NostrEventTemplate } from "nostr-tools";
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

/**
 * An implementation of NostrSigner based on a [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) browser extension.
 *
 * NOTE: `nip04/nip44`-`Encrypt/Decrypt` methods throw error if the underlying NIP-07 extension doesn't support them.
 */
export class Nip07ExtensionSigner implements NostrSigner {
  #nip07Ext: Nip07Extension;

  /**
   * Creates a Nip07ExtensionSigner from an instance of NIP-07 browser extension.
   *
   * @param nip07Ext an instance of NIP-07 extension (`window.nostr`)
   */
  public constructor(nip07Ext: Nip07Extension) {
    this.#nip07Ext = nip07Ext;
  }

  /**
   * Returns the public key that corresponds to the underlying secret key, in hex string format.
   */
  public async getPublicKey(): Promise<string> {
    return this.#nip07Ext.getPublicKey();
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
    return this.#nip07Ext.getRelays();
  }

  /**
   * Signs a given Nostr event with the underlying secret key.
   *
   * @param event a Nostr event template (unsigned event)
   * @returns a Promise that resolves to a signed Nostr event
   */
  public async signEvent(event: NostrEventTemplate): Promise<NostrEvent> {
    return this.#nip07Ext.signEvent(event);
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
    return this.#nip07Ext.nip04.encrypt(recipientPubkey, plaintext);
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
    return this.#nip07Ext.nip04.decrypt(senderPubkey, ciphertext);
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
    return this.#nip07Ext.nip44.encrypt(recipientPubkey, plaintext);
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
    return this.#nip07Ext.nip44.decrypt(senderPubkey, ciphertext);
  }
}
