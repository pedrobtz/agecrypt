# agecrypt 0.1.0

* Initial version.

## Fixes since the first submission

* Fixed silent data loss at the 8 KiB output-buffer boundary in the vendored
  `agec` I/O layer. Encrypting a payload of 7992-8192 bytes produced a
  truncated, undecryptable ciphertext, and decrypting a file whose final
  STREAM chunk was exactly 8192 bytes returned truncated plaintext with no
  error. Both reported success.
* Key files are now read, scanned and scrubbed in C. Previously the secret
  keys were read with `readLines()`, which interned them in R's global string
  cache for the life of the session.
* The scrypt work factor is validated in C as well as in R; an out-of-range
  value reaching the backend was undefined behaviour.
* `incnonce()` now increments the full 11-byte STREAM counter and reports a
  wrap instead of silently reusing a nonce.
* The shared native error buffer is reset at every entry point, so a failure
  can no longer report the previous operation's message.
* In-memory stream slots are released even if an R allocation fails and
  unwinds, and the recipient/identity entry points type-check their arguments
  before allocating.
