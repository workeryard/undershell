import { describe, expect, it } from "vitest";
import { bumpCounter, paddingFor } from "../src/transport";
import { concat, Reader, Writer } from "../src/wire";

describe("wire types", () => {
  it("writes a string as a length and then its bytes", () => {
    expect([...new Writer().string("abc").build()]).toEqual([0, 0, 0, 3, 97, 98, 99]);
  });

  it("reads back what it wrote", () => {
    const bytes = new Writer().byte(20).uint32(7).bool(true).string("hello").nameList(["a", "b"]).build();
    const reader = new Reader(bytes);
    expect(reader.byte()).toBe(20);
    expect(reader.uint32()).toBe(7);
    expect(reader.bool()).toBe(true);
    expect(reader.text()).toBe("hello");
    expect(reader.nameList()).toEqual(["a", "b"]);
    expect(reader.done).toBe(true);
  });

  it("reads an empty name list as no names, not one empty name", () => {
    expect(new Reader(new Writer().nameList([]).build()).nameList()).toEqual([]);
  });

  it("refuses to read past the end of a packet", () => {
    expect(() => new Reader(new Uint8Array([0, 0])).uint32()).toThrow(/ended early/);
    expect(() => new Reader(new Writer().uint32(10).build()).string()).toThrow(/ended early/);
  });

  describe("mpint", () => {
    it("drops leading zeros", () => {
      expect([...new Writer().mpint(new Uint8Array([0, 0, 5])).build()]).toEqual([0, 0, 0, 1, 5]);
    });

    it("adds a zero when the top bit is set, so the number stays positive", () => {
      expect([...new Writer().mpint(new Uint8Array([0x80])).build()]).toEqual([0, 0, 0, 2, 0, 0x80]);
    });

    it("writes zero as an empty string", () => {
      expect([...new Writer().mpint(new Uint8Array([0, 0])).build()]).toEqual([0, 0, 0, 0]);
    });

    it("leaves a number whose top bit is clear alone", () => {
      expect([...new Writer().mpint(new Uint8Array([0x7f, 0x01])).build()]).toEqual([0, 0, 0, 2, 0x7f, 1]);
    });
  });

  it("concatenates without sharing the inputs' buffers", () => {
    const first = new Uint8Array([1, 2]);
    const joined = concat([first, new Uint8Array([3])]);
    first[0] = 9;
    expect([...joined]).toEqual([1, 2, 3]);
  });
});

describe("packet padding", () => {
  it("fills to the block size, counting the length field when it is encrypted", () => {
    // 4 (length) + 1 (padding length) + 3 (payload) = 8, so a whole block of
    // padding has to be added to clear the four-byte minimum.
    expect(paddingFor(3, 8, true)).toBe(8);
    expect((4 + 1 + 3 + paddingFor(3, 8, true)) % 8).toBe(0);
  });

  it("leaves the length field out when the cipher authenticates it instead", () => {
    expect((1 + 10 + paddingFor(10, 16, false)) % 16).toBe(0);
    expect((1 + 16 + paddingFor(16, 16, false)) % 16).toBe(0);
  });

  it("never pads with fewer than the four bytes the protocol requires", () => {
    for (let payload = 0; payload < 64; payload++) {
      expect(paddingFor(payload, 16, false)).toBeGreaterThanOrEqual(4);
      expect(paddingFor(payload, 8, true)).toBeGreaterThanOrEqual(4);
    }
  });
});

describe("the GCM invocation counter", () => {
  it("counts up in the last eight bytes", () => {
    const iv = new Uint8Array(12);
    bumpCounter(iv);
    expect([...iv]).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  });

  it("carries into the next byte", () => {
    const iv = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff]);
    bumpCounter(iv);
    expect([...iv.subarray(10)]).toEqual([1, 0]);
  });

  it("leaves the four fixed bytes alone when the counter wraps", () => {
    const iv = new Uint8Array([1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    bumpCounter(iv);
    expect([...iv.subarray(0, 4)]).toEqual([1, 2, 3, 4]);
    expect([...iv.subarray(4)]).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  });
});
