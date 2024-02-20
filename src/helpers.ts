import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { decode as decodeNip19 } from "nostr-tools/nip19";

const regexHexKey = /^[0-9a-f]{64}$/;

// parse the given secret key of any string format (hex/bech32)
// returns undefined if the input is invalid
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

// parse the given public key of any string format (hex/bech32) as hex
// returns undefined if the input is invalid
export const parsePubkey = (pubkey: string): string | undefined => {
  if (pubkey.startsWith("npub1")) {
    return decodeNip19(pubkey as `npub1${string}`).data;
  }
  if (regexHexKey.test(pubkey)) {
    return pubkey;
  }
  return undefined;
};
