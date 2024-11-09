import type { Event as NostrEvent, EventTemplate as NostrEventTemplate } from "nostr-tools";

/**
 * The common interface of Nostr event signer.
 */
export type NostrSigner = {
  /**
   * Returns the public key that corresponds to the underlying secret key, in hex string format.
   */
  getPublicKey(): Promise<string>;

  /**
   * Returns the list of relays preferred by the user.
   *
   * Each entry is a mapping from the relay URL to the preferred use (read/write) of the relay.
   */
  getRelays(): Promise<RelayList>;

  /**
   * Signs a given Nostr event with the underlying secret key.
   *
   * @param event a Nostr event template (unsigned event)
   * @returns a Promise that resolves to a signed Nostr event
   */
  signEvent(event: NostrEventTemplate): Promise<NostrEvent>;

  /**
   * Encrypts a given text to secretly communicate with others, by the encryption algorithm defined in [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md).
   *
   * @param recipientPubkey a public key of a message recipient, in hex string format
   * @param plaintext a plaintext to encrypt
   * @returns a Promise that resolves to a encrypted text
   */
  nip04Encrypt(recipientPubkey: string, plaintext: string): Promise<string>;

  /**
   * Decrypts a given ciphertext from others, by the decryption algorithm defined in [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md).
   *
   * @param senderPubkey a public key of a message sender, in hex string format
   * @param ciphertext a ciphertext to decrypt
   * @returns a Promise that resolves to a decrypted text
   */
  nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string>;

  /**
   * Encrypts a given text to secretly communicate with others, by the encryption algorithm defined in [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md).
   * @param recipientPubkey a public key of a message recipient, in hex string format
   * @param plaintext a plaintext to encrypt
   */
  nip44Encrypt(recipientPubkey: string, plaintext: string): Promise<string>;

  /**
   * Decrypts a given ciphertext from others, by the decryption algorithm defined in [NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md).
   * @param senderPubkey a public key of a message sender, in hex string format
   * @param ciphertext a ciphertext to decrypt
   */
  nip44Decrypt(senderPubkey: string, ciphertext: string): Promise<string>;
};

export type RelayList = {
  [relayUrl: string]: { read: boolean; write: boolean };
};
