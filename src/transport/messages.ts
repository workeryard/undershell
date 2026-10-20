import { Reader, type Bytes } from '../wire';

/** Message numbers (RFC 4250 §4.1), by the names the RFCs give them. */
export const MSG = {
  DISCONNECT: 1,
  IGNORE: 2,
  UNIMPLEMENTED: 3,
  DEBUG: 4,
  SERVICE_REQUEST: 5,
  SERVICE_ACCEPT: 6,
  EXT_INFO: 7,
  KEXINIT: 20,
  NEWKEYS: 21,
  KEX_ECDH_INIT: 30,
  KEX_ECDH_REPLY: 31,
  USERAUTH_REQUEST: 50,
  USERAUTH_FAILURE: 51,
  USERAUTH_SUCCESS: 52,
  USERAUTH_BANNER: 53,
  /** Also USERAUTH_PK_OK and USERAUTH_PASSWD_CHANGEREQ: 60 means what the method in progress says. */
  USERAUTH_INFO_REQUEST: 60,
  USERAUTH_INFO_RESPONSE: 61,
  GLOBAL_REQUEST: 80,
  REQUEST_SUCCESS: 81,
  REQUEST_FAILURE: 82,
  CHANNEL_OPEN: 90,
  CHANNEL_OPEN_CONFIRMATION: 91,
  CHANNEL_OPEN_FAILURE: 92,
  CHANNEL_WINDOW_ADJUST: 93,
  CHANNEL_DATA: 94,
  CHANNEL_EXTENDED_DATA: 95,
  CHANNEL_EOF: 96,
  CHANNEL_CLOSE: 97,
  CHANNEL_REQUEST: 98,
  CHANNEL_SUCCESS: 99,
  CHANNEL_FAILURE: 100,
} as const;

export function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

export function disconnected(payload: Bytes): Error {
  const reader = new Reader(payload.subarray(1));
  const code = reader.uint32();
  return new Error(`the server disconnected (reason ${code}): ${reader.text()}`);
}

/** server-sig-algs from an EXT_INFO (RFC 8308 §3.1), or null if it has none. */
export function serverSignatureAlgorithms(payload: Bytes): string[] | null {
  const reader = new Reader(payload.subarray(1));
  const count = reader.uint32();
  let found: string[] | null = null;
  for (let index = 0; index < count; index++) {
    const name = reader.text();
    const value = reader.text();
    if (name === 'server-sig-algs') found = value.split(',');
  }
  return found;
}
