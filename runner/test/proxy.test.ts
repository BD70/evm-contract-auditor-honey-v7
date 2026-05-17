import { describe, expect, test } from "bun:test";
import { detectEip1167, resolveProxy } from "../src/proxy.js";

describe("proxy detection", () => {
  test("detects eip1167 implementation address", () => {
    const bytecode =
      "0x363d3d373d3d3d363d73aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa5af43d82803e903d91602b57fd5bf3";
    expect(detectEip1167(bytecode)).toEqual({
      implementationAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    });
  });

  test("resolves erc1967 implementation slot", async () => {
    const rpc = {
      getStorageAt: async (_address: string, slot: string) => {
        if (slot.endsWith("2bbc")) {
          return `0x${"0".repeat(24)}bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`;
        }
        return `0x${"0".repeat(64)}`;
      },
      ethCall: async () => "0x",
    };
    const result = await resolveProxy(rpc as never, "0xproxy", "0x60006000", 123);
    expect(result.detected).toBe(true);
    expect(result.proxyType).toBe("erc1967");
    expect(result.implementationAddress).toBe("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    expect(result.implementationResolved).toBe(true);
    expect(result.status).toBe("resolved");
  });

  test("marks unresolved structured delegatecall proxy explicitly", async () => {
    const rpc = {
      getStorageAt: async () => `0x${"0".repeat(64)}`,
      ethCall: async () => "0x",
    };
    const result = await resolveProxy(
      rpc as never,
      "0xproxy",
      "0x363d3d3760006000366000f43d82803e903d91602b57fd5bf3",
      123,
    );
    expect(result.detected).toBe(true);
    expect(result.proxyType).toBe("delegatecall_generic");
    expect(result.implementationResolved).toBe(false);
    expect(result.status).toBe("unresolved_safe");
    expect(result.unresolvedReason).toBe("delegatecall_proxy_without_safe_resolution");
  });

  test("does not treat arbitrary delegatecall bytecode as proxy shell", async () => {
    const rpc = {
      getStorageAt: async () => `0x${"0".repeat(64)}`,
      ethCall: async () => "0x",
    };
    const result = await resolveProxy(rpc as never, "0xproxy", "0x60016002f4600055", 123);
    expect(result.detected).toBe(false);
  });
});
