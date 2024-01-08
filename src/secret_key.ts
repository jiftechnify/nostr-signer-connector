import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  finalizeEvent,
  generateSecretKey,
  getPublicKey as nostrToolsGetPubkey,
  type Event as NostrEvent,
  type EventTemplate as NostrEventTemplate,
} from "nostr-tools";
import * as nip04 from "nostr-tools/nip04";
import type { NostrSigner } from "./interface";

/**
 * An implementation of NostrSigner based on a bare secret key in memory.
 *
 * You can make a SecretKeySigner in two ways:
 *
 * - via the constructor (`new SecretKeySigner(key)`), from secret keys in hex string or binary format.
 * - via `SecretKeySigner.withRandomKey()`, to make a signer with a random key.
 */
export class SecretKeySigner implements NostrSigner {
  #secKeyHex: string;
  #secKeyBytes: Uint8Array;

  /**
   * Makes a SecretKeySigner from a secret key in hex string format.
   *
   * @param secKeyHex a secret key in hex string
   */
  public constructor(secKeyHex: string);

  /**
   * Makes a SecretKeySigner from a secret key in binary format.
   *
   * @param secKeyBytes a secret key in binary format (`Uint8Array`)
   */
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

  /**
   * Makes a SecretKeySigner with a random secret key.
   */
  public static withRandomKey(): SecretKeySigner {
    return new SecretKeySigner(generateSecretKey());
  }

  /**
   * Returns the underlying secret key in hex string format.
   */
  public get secretKey(): string {
    return this.#secKeyHex;
  }

  /**
   * Returns the public key that corresponds to the underlying secret key, in hex string format.
   */
  public get publicKey(): string {
    return nostrToolsGetPubkey(this.#secKeyBytes);
  }

  /**
   * Returns the public key that corresponds to the underlying secret key, in hex string format.
   */
  public async getPublicKey(): Promise<string> {
    return this.publicKey;
  }

  /**
   * Signs a given Nostr event with the underlying secret key.
   *
   * @param event a Nostr event template (unsigned event)
   * @returns a Promise that resolves to a signed Nostr event
   */
  public async signEvent(event: NostrEventTemplate): Promise<NostrEvent> {
    return Promise.resolve(finalizeEvent(event, this.#secKeyBytes));
  }

  /**
   * Encrypts a given text to secretly communicate with others, by the encryption algorithm defined in [NIP-04]().
   *
   * @param recipientPubkey a public key of a message recipient, in hex string format
   * @param plaintext a plaintext to encrypt
   * @returns a Promise that resolves to a encrypted text
   */
  public async nip04Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    return nip04.encrypt(this.#secKeyHex, recipientPubkey, plaintext);
  }

  /**
   * Decrypts a given ciphertext from others, by the decryption algorithm defined in [NIP-04]().
   *
   * @param senderPubkey a public key of a message sender, in hex string format
   * @param ciphertext a ciphertext to decrypt
   * @returns a Promise that resolves to a decrypted text
   */
  public async nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return nip04.decrypt(this.#secKeyHex, senderPubkey, ciphertext);
  }
}
