import { describe, expect, test } from "bun:test";
import { parseAddressFromStorage, sha256Hex } from "../src/utils.js";
import { isWebhookRetryable } from "../src/webhook.js";

describe("runner utilities", () => {
  test("extracts address from storage word", () => {
    expect(parseAddressFromStorage(`0x${"0".repeat(24)}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`)).toBe(
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
  });

  test("hash is deterministic for dedupe", () => {
    expect(sha256Hex("abc")).toBe(sha256Hex("abc"));
  });

  test("classifies retryable webhook failures", () => {
    expect(isWebhookRetryable(new Error("webhook http 500"))).toBe(true);
    expect(isWebhookRetryable(new Error("webhook http 401"))).toBe(false);
  });
});
