Throwaway keys made for the tests with `ssh-keygen` (and one with `openssl
genpkey`), in every format the client reads. Nothing trusts them anywhere;
they are here because the point is to read what OpenSSH actually writes.
Each `.fingerprint` is what `ssh-keygen -lf` printed for the `.pub`.

Encrypted ones use the passphrase `fixture passphrase`.
