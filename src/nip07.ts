import { type Event as NostrEvent, type EventTemplate as NostrEventTemplate } from "nostr-tools";
import type { NostrSigner } from "./interface";

export type Nip07Extension = {
  getPublicKey(): Promise<string>;
  signEvent(event: NostrEventTemplate): Promise<NostrEvent>;
  nip04?: {
    encrypt(pubKey: string, value: string): Promise<string>;
    decrypt(pubKey: string, value: string): Promise<string>;
  };
};

/**
 * An implementation of NostrSigner based on a [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) browser extension.
 *
 * NOTE: `nip04Encrypt` and `nip04Decrypt` throws error if the underlying NIP-07 extension doesn't support the NIP-04 capabilities.
 */
export class Nip07ExtensionSigner implements NostrSigner {
  #nip07Ext: Nip07Extension;

  /**
   * Makes a Nip07ExtensionSigner from an instance of NIP-07 browser extension.
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
    if (this.#nip07Ext.nip04 === undefined) {
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
    if (this.#nip07Ext.nip04 === undefined) {
      throw Error("NIP-07 browser extension doesn't support nip04.decrypt");
    }
    return this.#nip07Ext.nip04.decrypt(senderPubkey, ciphertext);
  }
}
