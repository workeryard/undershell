import { describe, expect, it } from "vitest";
import { parseOpenSshPrivateKey } from "../src/openssh-key";

/**
 * A real `ssh-keygen -t ed25519 -N "correct horse battery staple"` file. It is
 * a throwaway generated for this test and used by nothing: what matters is
 * that it is OpenSSH's own output rather than something built here, since the
 * point is reading what OpenSSH writes.
 */
const LOCKED = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB1w072hl
hzc1SIxn22mP3/AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIG/JlBOFsVGu3CO6
0t/2WCErSRgbJVrtWoDA5xDuXFAsAAAAkL7BRWjE7FzCpKUamgTNdwZU79x7slcRegw6Pt
8txN3y9zebuurPdI0HguUBnLG/iFA1j1YZATq4BvaWyEbwmJinMlmi8PO7Xxc9XLnw9Xo0
+UwIR//nb+XsnADcL9x6WXCY6bbNEcXrpGZDbLB1eU9gD+vTknnU//Dhu0c7nbQqQ/zuVc
F0095rhr3LEX4m/g==
-----END OPENSSH PRIVATE KEY-----`;

const PASSPHRASE = "correct horse battery staple";

describe("a key with a passphrase", () => {
  it("opens with the right one", async () => {
    const key = await parseOpenSshPrivateKey(LOCKED, PASSPHRASE);
    expect(key.signingKey.algorithm.name).toBe("Ed25519");
    const signature = await crypto.subtle.sign({ name: "Ed25519" }, key.signingKey, new Uint8Array([1]));
    expect(signature.byteLength).toBe(64);
  });

  it("says the passphrase is wrong rather than failing obscurely", async () => {
    await expect(parseOpenSshPrivateKey(LOCKED, "not it")).rejects.toThrow(/passphrase does not open this key/);
  });

  it("says one is needed when none is given", async () => {
    await expect(parseOpenSshPrivateKey(LOCKED)).rejects.toThrow(/has a passphrase, and none was given/);
  });

  it("recovers the same public key the file carries", async () => {
    const key = await parseOpenSshPrivateKey(LOCKED, PASSPHRASE);
    expect(key.publicKeyBlob.length).toBe(4 + "ssh-ed25519".length + 4 + 32);
  });
});
