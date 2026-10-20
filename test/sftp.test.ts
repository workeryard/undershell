import { describe, expect, it } from "vitest";
import { Sftp } from "../src/sftp";
import { MSG, type Transport } from "../src/transport";
import { concat, Reader, Writer, type Bytes } from "../src/wire";

/**
 * A transport that plays a scripted server. What is under test is the framing:
 * SFTP packets have their own lengths and arrive inside channel messages that
 * respect neither, so one packet can span two messages and two can share one.
 */
class Scripted {
  readonly sent: Bytes[] = [];
  #queue: Bytes[] = [];

  constructor(private readonly reply: (packet: { type: number; id: number; reader: Reader }) => Bytes[]) {}

  /** Wraps an SFTP packet in however many channel messages were asked for. */
  static channelData(packet: Bytes, pieces = 1): Bytes[] {
    const framed = concat([new Writer().uint32(packet.length).build(), packet]);
    const size = Math.ceil(framed.length / pieces);
    const out: Bytes[] = [];
    for (let at = 0; at < framed.length; at += size) {
      out.push(
        new Writer()
          .byte(MSG.CHANNEL_DATA)
          .uint32(0)
          .string(framed.subarray(at, at + size))
          .build(),
      );
    }
    return out;
  }

  async send(payload: Bytes): Promise<void> {
    this.sent.push(payload);
    const type = payload[0];
    if (type === MSG.CHANNEL_OPEN) {
      this.#queue.push(
        new Writer()
          .byte(MSG.CHANNEL_OPEN_CONFIRMATION)
          .uint32(0)
          .uint32(7)
          .uint32(1 << 20)
          .uint32(32768)
          .build(),
      );
      return;
    }
    if (type === MSG.CHANNEL_REQUEST) {
      this.#queue.push(new Uint8Array([MSG.CHANNEL_SUCCESS, 0, 0, 0, 0]));
      return;
    }
    if (type === MSG.CHANNEL_DATA) {
      const reader = new Reader(payload.subarray(1));
      reader.uint32();
      const data = reader.string();
      const packet = data.subarray(4);
      const inner = new Reader(packet.slice(1));
      const id = packet[0] === 1 ? 0 : inner.uint32();
      this.#queue.push(...this.reply({ type: packet[0]!, id, reader: inner }));
    }
  }

  async receive(): Promise<Bytes> {
    const next = this.#queue.shift();
    if (!next) throw new Error("the script ran out");
    return next;
  }
}

const VERSION = () => Scripted.channelData(new Writer().byte(2).uint32(3).build());
const HANDLE = (id: number) => new Writer().byte(102).uint32(id).string("h").build();
const STATUS_EOF = (id: number) => new Writer().byte(101).uint32(id).uint32(1).string("").string("").build();
const OK = (id: number) => new Writer().byte(101).uint32(id).uint32(0).string("").string("").build();

function names(id: number, entries: [string, number, number][]): Bytes {
  const writer = new Writer().byte(104).uint32(id).uint32(entries.length);
  for (const [name, size, permissions] of entries) {
    writer.string(name).string(`-rw-r--r-- 1 x x ${size} ${name}`);
    writer
      .uint32(0x1 | 0x4)
      .uint32(0)
      .uint32(size)
      .uint32(permissions);
  }
  return writer.build();
}

describe("an sftp session", () => {
  it("lists a directory, over packets the channel split up", async () => {
    let step = 0;
    const script = new Scripted(({ type, id }) => {
      if (type === 1) return VERSION();
      if (type === 11) return Scripted.channelData(HANDLE(id));
      if (type === 12) {
        step++;
        // The first answer is delivered in three pieces, so reassembly is
        // exercised rather than assumed.
        if (step === 1) {
          return Scripted.channelData(
            names(id, [
              ["a.csv", 10, 0o100644],
              ["logs", 0, 0o040755],
              [".", 0, 0o040755],
            ]),
            3,
          );
        }
        return Scripted.channelData(STATUS_EOF(id));
      }
      if (type === 4) return Scripted.channelData(OK(id));
      throw new Error(`the script has no answer for packet type ${type}`);
    });

    const sftp = await Sftp.open(script as unknown as Transport);
    const entries = await sftp.list("/home/x");
    expect(entries).toEqual([
      { name: "a.csv", size: 10, directory: false, modifiedAt: null },
      { name: "logs", size: 0, directory: true, modifiedAt: null },
    ]);
  });

  it("repeats what the server said when it refuses", async () => {
    const script = new Scripted(({ type, id }) => {
      if (type === 1) return VERSION();
      if (type === 3) {
        return Scripted.channelData(
          new Writer().byte(101).uint32(id).uint32(3).string("Permission denied").string("").build(),
        );
      }
      throw new Error(`the script has no answer for packet type ${type}`);
    });
    const sftp = await Sftp.open(script as unknown as Transport);
    await expect(sftp.get("/root/secret")).rejects.toThrow(/Permission denied/);
  });

  it("names the code when the server sends no message of its own", async () => {
    const script = new Scripted(({ type, id }) => {
      if (type === 1) return VERSION();
      if (type === 3)
        return Scripted.channelData(new Writer().byte(101).uint32(id).uint32(2).string("").string("").build());
      throw new Error(`the script has no answer for packet type ${type}`);
    });
    const sftp = await Sftp.open(script as unknown as Transport);
    await expect(sftp.get("/nope")).rejects.toThrow(/no such file/);
  });

  it("refuses a server too old to speak version 3", async () => {
    const script = new Scripted(({ type }) => {
      if (type === 1) return Scripted.channelData(new Writer().byte(2).uint32(2).build());
      throw new Error("unreachable");
    });
    await expect(Sftp.open(script as unknown as Transport)).rejects.toThrow(/speaks sftp 2/);
  });
});
