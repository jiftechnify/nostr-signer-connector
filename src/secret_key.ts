import { bytesToHex } from "@noble/hashes/utils";
import {
  type Event as NostrEvent,
  type EventTemplate as NostrEventTemplate,
  finalizeEvent,
  generateSecretKey,
  getPublicKey as nostrToolsGetPubkey,
} from "nostr-tools";
import * as nip04 from "nostr-tools/nip04";
import { parseSecKey } from "./helpers";
import type { NostrSigner } from "./interface";

/**
 * An implementation of NostrSigner based on a bare secret key in memory.
 *
 * You can create a SecretKeySigner in two ways:
 *
 * - via the constructor (`new SecretKeySigner(key)`), from secret keys in hex string, bech32 (`nsec1...`) or binary format.
 * - via `SecretKeySigner.withRandomKey()`, to make a signer with a random key.
 */
export class SecretKeySigner implements NostrSigner {
  #secKeyHex: string;
  #secKeyBytes: Uint8Array;

  /**
   * Creates a SecretKeySigner from a secret key in hex string or bech32 (`nsec1...`) format.
   *
   * @param secKeyStr a secret key in hex string or bech32 format
   */
  public constructor(secKeyStr: string);

  /**
   * Creates a SecretKeySigner from a secret key in binary format.
   *
   * @param secKeyBytes a secret key in binary format (`Uint8Array`)
   */
  public constructor(secKeyBytes: Uint8Array);

  public constructor(secKey: string | Uint8Array) {
    if (typeof secKey === "string") {
      const res = parseSecKey(secKey);
      if (res === undefined) {
        throw Error("SecretKeySigner: constructor got an invalid secret key");
      }
      this.#secKeyHex = res.hex;
      this.#secKeyBytes = res.bytes;
    } else {
      // secret key must be 32 bytes length.
      if (secKey.length !== 32) {
        throw Error("SecretKeySigner: constructor got an invalid secret key");
      }
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
   * Encrypts a given text to secretly communicate with others, by the encryption algorithm defined in [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md).
   *
   * @param recipientPubkey a public key of a message recipient, in hex string format
   * @param plaintext a plaintext to encrypt
   * @returns a Promise that resolves to a encrypted text
   */
  public async nip04Encrypt(recipientPubkey: string, plaintext: string): Promise<string> {
    return nip04.encrypt(this.#secKeyHex, recipientPubkey, plaintext);
  }

  /**
   * Decrypts a given ciphertext from others, by the decryption algorithm defined in [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md).
   *
   * @param senderPubkey a public key of a message sender, in hex string format
   * @param ciphertext a ciphertext to decrypt
   * @returns a Promise that resolves to a decrypted text
   */
  public async nip04Decrypt(senderPubkey: string, ciphertext: string): Promise<string> {
    return nip04.decrypt(this.#secKeyHex, senderPubkey, ciphertext);
  }
}
