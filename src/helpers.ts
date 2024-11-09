import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as nip19 from "nostr-tools/nip19";

const regexHexKey = /^[0-9a-f]{64}$/;

/**
 * Parses the given secret key of any string format (hex/bech32)
 * @returns Secret key as both a hex string and an array of bytes, or undefined if the input is invalid
 */
export const parseSecKey = (secKey: string): { hex: string; bytes: Uint8Array } | undefined => {
  if (secKey.startsWith("nsec1")) {
    const bytes = nip19.decode(secKey as `nsec1${string}`).data;
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
    return nip19.decode(pubkey as `npub1${string}`).data;
  }
  if (regexHexKey.test(pubkey)) {
    return pubkey;
  }
  return undefined;
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
