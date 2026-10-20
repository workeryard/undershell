# Security

Please report a vulnerability privately, not in a public issue: open this
repository's **Security** tab and choose **Report a vulnerability**. You will
hear back within a week.

What counts here:

- a host key, signature or fingerprint that should be refused and is not,
  on the first exchange or a re-key;
- a packet that is accepted though its MAC or GCM tag is wrong, or a
  sequence that strict KEX should have stopped;
- a nonce or counter used twice, or keys derived wrongly;
- a private key, passphrase, password or keyboard-interactive answer
  reaching anywhere it was not sent to;
- a server able to make the client hold unbounded memory, or do work it
  should not: overrunning a window, a packet past the limits, a loop of
  prompts.

A server that cannot be reached because it offers only what this client
does not (SHA-1, CBC, ChaCha20) is not a security issue; open an ordinary
issue for it.

Fixes go into the latest release. Older releases are not patched.
