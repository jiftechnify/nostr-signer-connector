import { describe, expect, test } from "vitest";
import { parseBunkerToken } from "./signer";

const testPubkey = {
  hex: "d1d1747115d16751a97c239f46ec1703292c3b7e9988b9ebdd4ec4705b15ed44",
  npub: "npub168ghgug469n4r2tuyw05dmqhqv5jcwm7nxytn67afmz8qkc4a4zqsu2dlc",
};

describe("parseBunkerToken", () => {
  describe("should parse bunker:// token", () => {
    test("minimal", () => {
      const { remotePubkey, relayUrls, secretToken } = parseBunkerToken(
        `bunker://${testPubkey.npub}?relay=wss%3A%2F%2Fyabu.me&relay=wss%3A%2F%2Fnrelay.c-stellar.net`,
      );
      expect(remotePubkey).toBe(testPubkey.hex);
      expect(relayUrls).toEqual(["wss://yabu.me", "wss://nrelay.c-stellar.net"]);
      expect(secretToken).toBeUndefined();
    });
    test("with secret", () => {
      const { remotePubkey, relayUrls, secretToken } = parseBunkerToken(
        `bunker://${testPubkey.npub}?relay=wss%3A%2F%2Fyabu.me&relay=wss%3A%2F%2Fnrelay.c-stellar.net&secret=123456`,
      );
      expect(remotePubkey).toBe(testPubkey.hex);
      expect(relayUrls).toEqual(["wss://yabu.me", "wss://nrelay.c-stellar.net"]);
      expect(secretToken).toBe("123456");
    });
  });

  describe("should throw error when invalid connection token", () => {
    test("invalid schema", () => {
      expect(() => {
        parseBunkerToken(
          `invalid://${testPubkey.npub}?relay=wss%3A%2F%2Fyabu.me&relay=wss%3A%2F%2Fnrelay.c-stellar.net&secret=123456`,
        );
      }).toThrowError();
    });
    test("invalid pubkey", () => {
      expect(() => {
        parseBunkerToken("bunker://hoge");
      }).toThrowError();
    });
    test("no parameters", () => {
      expect(() => {
        parseBunkerToken(`bunker://${testPubkey.npub}`);
      }).toThrowError();
    });
    test("no relay URLs", () => {
      expect(() => {
        parseBunkerToken(`bunker://${testPubkey.npub}?secret=123456`);
      }).toThrowError();
    });
    test("legacy token format", () => {
      expect(() => {
        parseBunkerToken(`${testPubkey.hex}#123456?relay=wss%3A%2F%2Fyabu.me&relay=wss%3A%2F%2Fnrelay.c-stellar.net`);
      }).toThrowError();
    });
  });
});
