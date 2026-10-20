/**
 * Reading an `id_ed25519` as OpenSSH writes it. The file is its own container
 * format ("openssh-key-v1"), not PEM/PKCS#8, so WebCrypto cannot be handed it
 * directly: the 32-byte seed has to be dug out and wrapped.
 *
 * A key with a passphrase is unlocked here too. `ssh-keygen` protects one with
 * bcrypt-pbkdf, which WebCrypto has no primitive for, so that one derivation
 * comes from a package; everything after it is AES-CTR, which it does have.
 */

/// <reference path="./bcrypt-pbkdf.d.ts" />
import bcryptPbkdf from "bcrypt-pbkdf";
import { subtle } from "./crypto";
import { Reader, type Bytes } from "./wire";

const MAGIC = "openssh-key-v1\0";

/** What `ssh-keygen` writes. CBC is refused rather than half-supported. */
const CIPHERS: Record<string, { keyLength: number }> = {
  "aes256-ctr": { keyLength: 32 },
  "aes192-ctr": { keyLength: 24 },
  "aes128-ctr": { keyLength: 16 },
};

/** PKCS#8 for Ed25519 is this fixed prefix and then the seed. */
const PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export interface PrivateKey {
  /** The blob as it goes on the wire: string "ssh-ed25519", string <32 bytes>. */
  publicKeyBlob: Bytes;
  signingKey: CryptoKey;
}

function base64ToBytes(base64: string): Bytes {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) out[index] = binary.charCodeAt(index);
  return out;
}

/**
 * The bcrypt-pbkdf derivation OpenSSH uses, then AES-CTR over the private
 * section. Whether the passphrase was right is not known here: the two check
 * values inside the plaintext are what says so, which is why they are compared
 * below rather than trusted.
 */
async function unlock(blob: Bytes, cipher: string, kdf: string, options: Bytes, passphrase: string): Promise<Bytes> {
  const spec = CIPHERS[cipher];
  if (!spec) throw new Error(`the key is encrypted with ${cipher}, which this client cannot read`);
  if (kdf !== "bcrypt") throw new Error(`the key uses the ${kdf} derivation, which this client cannot read`);
  if (!passphrase) throw new Error("the key has a passphrase, and none was given");

  const reader = new Reader(options);
  const salt = reader.string();
  const rounds = reader.uint32();

  // 16 bytes of IV follow the key, and AES-CTR counts over the whole block.
  const material = new Uint8Array(spec.keyLength + 16);
  bcryptPbkdf.pbkdf(
    new TextEncoder().encode(passphrase),
    passphrase.length,
    salt,
    salt.length,
    material,
    material.length,
    rounds,
  );

  const key = await subtle.importKey("raw", material.subarray(0, spec.keyLength), { name: "AES-CTR" }, false, [
    "decrypt",
  ]);
  const plain = await subtle.decrypt(
    { name: "AES-CTR", counter: material.subarray(spec.keyLength), length: 128 },
    key,
    blob,
  );
  return new Uint8Array(plain);
}

export async function parseOpenSshPrivateKey(text: string, passphrase = ""): Promise<PrivateKey> {
  const body = text
    .split("\n")
    .filter((line) => !line.startsWith("-----") && line.trim() !== "")
    .join("");
  const reader = new Reader(base64ToBytes(body));

  const magic = new TextDecoder().decode(reader.bytes.subarray(0, MAGIC.length));
  if (magic !== MAGIC) throw new Error("not an OpenSSH private key");
  for (let index = 0; index < MAGIC.length; index++) reader.byte();

  const cipher = reader.text();
  const kdf = reader.text();
  const kdfOptions = reader.string();
  const locked = cipher !== "none";

  const count = reader.uint32();
  if (count !== 1) throw new Error(`expected one key in the file, found ${count}`);
  const publicKeyBlob = reader.string();

  const section = reader.string();
  const secret = new Reader(locked ? await unlock(section, cipher, kdf, kdfOptions, passphrase) : section);
  if (secret.uint32() !== secret.uint32()) {
    // The format has no other way to tell a wrong passphrase from a corrupt file.
    throw new Error(locked ? "the passphrase does not open this key" : "the key did not decrypt (check values differ)");
  }
  const type = secret.text();
  if (type !== "ssh-ed25519") throw new Error(`only ssh-ed25519 keys are read here, this is ${type}`);
  secret.skipString(); // the public key again
  const priv = secret.string(); // seed (32) || public key (32)
  if (priv.length !== 64) throw new Error(`expected a 64-byte private part, got ${priv.length}`);

  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + 32);
  pkcs8.set(PKCS8_PREFIX);
  pkcs8.set(priv.subarray(0, 32), PKCS8_PREFIX.length);
  const signingKey = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);

  return { publicKeyBlob, signingKey };
}
