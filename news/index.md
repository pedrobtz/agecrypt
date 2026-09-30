# Changelog

## agecrypt 0.1.1

### Bug fixes

- Fixed silent data loss at the 8 KiB output-buffer boundary. Encrypting
  a payload of about 8 KB (7992 to 8192 bytes) produced a truncated
  ciphertext that could not be decrypted, and decrypting a file whose
  final chunk was exactly 8 KiB (for example, a 73728-byte plaintext)
  returned truncated plaintext. Both reported success. Ciphertexts of
  about 8 KB that were created with 0.1.0 may be unrecoverable;
  decrypt-and-compare any you rely on.

- Error messages now describe the failure that happened. Previously a
  failure could report the message of an earlier, unrelated operation.

### Security

- Identity files are read, parsed, and scrubbed in native code.
  Previously the secret key lines passed through
  [`readLines()`](https://rdrr.io/r/base/readLines.html), which kept
  them in R’s global string cache for the rest of the session.

- The vendored ‘agec’ library is updated to version 1.0.0. Headers are
  now parsed more strictly, as the age specification requires: stanzas
  with malformed bodies are rejected, including those of unrecognized
  types.

- The payload nonce counter now spans all 11 bytes that the age
  specification defines, and a counter overflow is reported instead of
  reusing a nonce. No reachable payload size is affected.

- The native code no longer leaks internal buffers, or leaves a decoded
  secret on the stack, when an operation fails part way.

### Other changes

- agecrypt now requires R 3.5.0 or later.

## agecrypt 0.1.0

CRAN release: 2026-08-05

- Initial version.
