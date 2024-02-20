import { describe, expect, test } from "vitest";
import { parseConnToken } from "./nip46";

const testPubkey = {
  hex: "d1d1747115d16751a97c239f46ec1703292c3b7e9988b9ebdd4ec4705b15ed44",
  npub: "npub168ghgug469n4r2tuyw05dmqhqv5jcwm7nxytn67afmz8qkc4a4zqsu2dlc",
};

describe("parseConnToken", () => {
  describe("should parse bunker:// token", () => {
    test("pubkey only", () => {
      const { remotePubkey, relayUrls, secretToken } = parseConnToken(`bunker://${testPubkey.npub}`);
      expect(remotePubkey).toBe(testPubkey.hex);
      expect(relayUrls).toHaveLength(0);
      expect(secretToken).toBeUndefined();
    });
    test("pubkey, relay URLs and secret token", () => {
      const { remotePubkey, relayUrls, secretToken } = parseConnToken(
        `bunker://${testPubkey.npub}?relay=wss%3A%2F%2Fyabu.me&relay=wss%3A%2F%2Fnrelay.c-stellar.net&secret=123456`,
      );
      expect(remotePubkey).toBe(testPubkey.hex);
      expect(relayUrls).toEqual(["wss://yabu.me", "wss://nrelay.c-stellar.net"]);
      expect(secretToken).toBe("123456");
    });
  });

  describe("should parse legacy token", () => {
    test("pubkey only", () => {
      const { remotePubkey, relayUrls, secretToken } = parseConnToken(`${testPubkey.hex}`);
      expect(remotePubkey).toBe(testPubkey.hex);
      expect(secretToken).toBeUndefined();
      expect(relayUrls).toHaveLength(0);
    });
    test("pubkey and secret token", () => {
      const { remotePubkey, relayUrls, secretToken } = parseConnToken(`${testPubkey.hex}#123456`);
      expect(remotePubkey).toBe(testPubkey.hex);
      expect(secretToken).toBe("123456");
      expect(relayUrls).toHaveLength(0);
    });
    test("pubkey and relay URLs", () => {
      const { remotePubkey, relayUrls, secretToken } = parseConnToken(
        `${testPubkey.hex}?relay=wss%3A%2F%2Fyabu.me&relay=wss%3A%2F%2Fnrelay.c-stellar.net`,
      );
      expect(remotePubkey).toBe(testPubkey.hex);
      expect(secretToken).toBeUndefined();
      expect(relayUrls).toEqual(["wss://yabu.me", "wss://nrelay.c-stellar.net"]);
    });
    test("pubkey, relay URLs and secret token", () => {
      const { remotePubkey, relayUrls, secretToken } = parseConnToken(
        `${testPubkey.hex}#123456?relay=wss%3A%2F%2Fyabu.me&relay=wss%3A%2F%2Fnrelay.c-stellar.net`,
      );
      expect(remotePubkey).toBe(testPubkey.hex);
      expect(secretToken).toBe("123456");
      expect(relayUrls).toEqual(["wss://yabu.me", "wss://nrelay.c-stellar.net"]);
    });
  });

  describe("should throw error when invalid connection token", () => {
    test("URL token: invalid schema", () => {
      expect(() => {
        parseConnToken(
          `invalid://${testPubkey.npub}?relay=wss%3A%2F%2Fyabu.me&relay=wss%3A%2F%2Fnrelay.c-stellar.net&secret=123456`,
        );
      }).toThrowError();
    });
    test("URL token: invalid pubkey", () => {
      expect(() => {
        parseConnToken(`bunker://hoge`);
      }).toThrowError();
    });
    test("legacy token: invalid pubkey", () => {
      expect(() => {
        parseConnToken(`hoge#123456`);
      }).toThrowError();
    });
  });
});
