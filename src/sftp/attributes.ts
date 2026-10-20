/** File attributes as SFTP version 3 sends them (draft-ietf-secsh-filexfer-02 §5). */

import { Writer, type Reader } from '../wire';

const SIZE = 0x1;
const UIDGID = 0x2;
const PERMISSIONS = 0x4;
const ACMODTIME = 0x8;
const EXTENDED = 0x80000000;

/** The type bits of a mode, as stat(2) has them. */
const TYPE_MASK = 0o170000;
const DIRECTORY = 0o040000;
const FILE = 0o100000;
const LINK = 0o120000;

export interface Stats {
  /** Bytes; null when the server sent no size. */
  size: number | null;
  uid: number | null;
  gid: number | null;
  /** The whole mode, type bits included; null when the server sent none. */
  permissions: number | null;
  /** Seconds since the epoch, or null when the server sent no times. */
  accessedAt: number | null;
  modifiedAt: number | null;
  isDirectory: boolean;
  isFile: boolean;
  isSymbolicLink: boolean;
}

export function readAttributes(reader: Reader): Stats {
  const flags = reader.uint32();
  const stats: Stats = {
    size: null,
    uid: null,
    gid: null,
    permissions: null,
    accessedAt: null,
    modifiedAt: null,
    isDirectory: false,
    isFile: false,
    isSymbolicLink: false,
  };
  if (flags & SIZE) stats.size = reader.uint64();
  if (flags & UIDGID) {
    stats.uid = reader.uint32();
    stats.gid = reader.uint32();
  }
  if (flags & PERMISSIONS) {
    const mode = reader.uint32();
    stats.permissions = mode;
    stats.isDirectory = (mode & TYPE_MASK) === DIRECTORY;
    stats.isFile = (mode & TYPE_MASK) === FILE;
    stats.isSymbolicLink = (mode & TYPE_MASK) === LINK;
  }
  if (flags & ACMODTIME) {
    stats.accessedAt = reader.uint32();
    stats.modifiedAt = reader.uint32();
  }
  if (flags & EXTENDED) {
    const count = reader.uint32();
    for (let index = 0; index < count; index++) {
      reader.skipString();
      reader.skipString();
    }
  }
  return stats;
}

/** Attributes to send: only a mode, which is all mkdir and open are given here. */
export function writeAttributes(writer: Writer, mode?: number): Writer {
  return mode === undefined ? writer.uint32(0) : writer.uint32(PERMISSIONS).uint32(mode);
}
