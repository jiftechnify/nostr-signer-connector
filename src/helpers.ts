import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { decode as decodeNip19 } from "nostr-tools/nip19";
import type { NostrSigner } from "./interface";

const regexHexKey = /^[0-9a-f]{64}$/;

/**
 * Parses the given secret key of any string format (hex/bech32)
 * @returns Secret key as both a hex string and an array of bytes, or undefined if the input is invalid
 */
export const parseSecKey = (secKey: string): { hex: string; bytes: Uint8Array } | undefined => {
  if (secKey.startsWith("nsec1")) {
    const bytes = decodeNip19(secKey as `nsec1${string}`).data;
    return {
      hex: bytesToHex(bytes),
      bytes,
    };
  }
  if (regexHexKey.test(secKey)) {
    return {
      hex: secKey,
      bytes: hexToBytes(secKey),
    };
  }
  return undefined;
};

/**
 * Parses the given public key of any string format (hex/bech32) as hex
 * @returns Public key as a hex string, or undefined if the input is invalid
 */
export const parsePubkey = (pubkey: string): string | undefined => {
  if (pubkey.startsWith("npub1")) {
    return decodeNip19(pubkey as `npub1${string}`).data;
  }
  if (regexHexKey.test(pubkey)) {
    return pubkey;
  }
  return undefined;
};

/**
 * Detects encryption algorithm (NIP-04 or NIP-44) of the ciphertext smartly, then decrypts it with corresponding decryption algorithm.
 */
export const smartDecrypt = (signer: NostrSigner, senderPubkey: string, ciphertext: string): Promise<string> => {
  const lastPart = ciphertext.split("?iv=").at(-1);
  if (lastPart !== undefined && lastPart.length === 24) {
    // ciphertext has an IV part, so assuming it's NIP-04 encrypted
    return signer.nip04Decrypt(senderPubkey, ciphertext);
  }
  return signer.nip44Decrypt(senderPubkey, ciphertext);
};

/**
 * Current Unix timestamp in seconds.
 */
export const currentUnixtimeSec = () => Math.floor(Date.now() / 1000);

export const generateRandomString = () => Math.random().toString(32).substring(2, 8);

export interface Deferred<T> {
  resolve(v: T | PromiseLike<T>): void;
  reject(e?: unknown): void;
}

// biome-ignore lint/suspicious/noUnsafeDeclarationMerging:
export class Deferred<T> {
  promise: Promise<T>;
  constructor() {
    this.promise = new Promise((resolve, reject) => {
      this.resolve = (v) => {
        resolve(v);
      };
      this.reject = (e) => {
        reject(e);
      };
    });
  }
}

export const delay = (durationMs: number) => new Promise((resolve) => setTimeout(resolve, durationMs));

export const mergeOptionsWithDefaults = <T>(defaults: Required<T>, opts: T): Required<T> => ({ ...defaults, ...opts });
