# Package design

This document describes the intended public behavior of `agecrypt`. Generated
function reference pages remain authoritative for exact argument signatures.
Implementation details are in [architecture.md](architecture.md).

## Goals

`agecrypt` provides an idiomatic R interface to the
[age v1 format](https://age-encryption.org/v1) through a single vendored native
backend. It supports in-memory secret workflows and constant-memory file
encryption without requiring an external `age` binary or cryptographic library.

## Design principles

1. Use age terminology: a public key is a **recipient** and a private key is an
   **identity**.
2. Prefix public functions with `age_` and use explicit verbs.
3. Hide protocol internals such as X25519, HKDF, stanzas, header MACs, and STREAM
   nonces.
4. Use raw-vector transformations as the composable primitive while giving file
   operations a dedicated streaming path.
5. Prevent accidental secret disclosure and silent file overwrites.
6. Return structured conditions that distinguish input, authentication, and I/O
   failures.
7. Keep recipient and passphrase modes as separate functions.
8. Keep hard R dependencies at zero; `askpass` is optional for interactive
   prompting.

## Public surface

### Identity and recipient functions

```r
age_keygen(path = NULL, overwrite = FALSE)
age_pubkey(identities)
age_identity(x)
age_identity_free(identity)
```

- `age_keygen()` returns an opaque `age_identity` and can write a standard age
  keyfile when `path` is supplied.
- `age_pubkey()` returns plain `"age1..."` character strings.
- `age_identity()` accepts inline `"AGE-SECRET-KEY-1..."` values, keyfile paths,
  or vectors mixing both. Keyfiles may hold multiple identities.
- `age_identity_free()` explicitly scrubs and frees a parsed identity before
  garbage collection.
- Every `identities=` argument accepts either a parsed `age_identity` or the same
  character input accepted by `age_identity()`.
- Every `recipients=` argument is a character vector of `"age1..."` values.

### Recipient encryption

```r
age_encrypt_raw(x, recipients, armor = FALSE)
age_decrypt_raw(x, identities)

age_encrypt_file(input, output = NULL, recipients, armor = FALSE,
                 overwrite = FALSE)
age_decrypt_file(input, output = NULL, identities, overwrite = FALSE)

age_encrypt_text(x, recipients, armor = TRUE)
age_decrypt_text(x, identities)
```

Raw functions always return raw vectors, including armored output.
`age_decrypt_raw()` also accepts a length-one armored character string. Text
helpers operate on one string, encode plaintext as UTF-8, and return one string.

File encryption appends `.age` when `output` is omitted. File decryption strips
a trailing `.age`; if the input does not end in `.age`, callers must supply an
output explicitly. File functions return the output path invisibly and do not
overwrite by default.

### Passphrase encryption

```r
age_encrypt_raw_passphrase(x, passphrase = NULL, armor = FALSE, log_n = 18)
age_decrypt_raw_passphrase(x, passphrase = NULL)

age_encrypt_file_passphrase(input, output = NULL, passphrase = NULL,
                            armor = FALSE, overwrite = FALSE, log_n = 18)
age_decrypt_file_passphrase(input, output = NULL, passphrase = NULL,
                            overwrite = FALSE)
```

Passphrase mode uses scrypt and cannot be mixed with recipient mode.
`passphrase = NULL` prompts through `askpass` only in an interactive session and
errors instead of waiting in non-interactive sessions. `log_n` is validated from
2 through 22; decryption rejects files above the same work-factor limit.

## Identity secrecy

`age_identity` is an S3 wrapper around an opaque native pointer. Its printed and
formatted forms contain public recipients only. There is intentionally no
default secret exporter or character coercion. See
[architecture.md](architecture.md#identity-lifecycle-and-secrecy) for the
native lifecycle.

## Errors

All package errors inherit from `age_error`:

| Class | Meaning |
|---|---|
| `age_error_recipient` | Invalid recipient input |
| `age_error_identity` | Invalid inline identity or unreadable/malformed keyfile |
| `age_error_encrypt` | Encryption failed after input validation |
| `age_error_decrypt` | No matching identity, invalid header, or authentication failure |
| `age_error_io` | File open, read, or write failure |

This separation lets callers distinguish misconfiguration, corrupt or
unauthenticated ciphertext, and retryable storage problems.

## Supported features

- X25519 recipients, including multiple recipients and identities.
- Scrypt passphrases with bounded work factors.
- Binary and ASCII-armored ciphertext.
- Raw-vector, text, and streaming file I/O.
- Interoperability with the age v1 format.

## Planned work

### R object helpers

Encrypted R-object helpers should compose over the raw primitives so plaintext
never needs a temporary file:

```r
saveRDS_age <- function(object, file, recipients, armor = FALSE) {
  cipher <- age_encrypt_raw(serialize(object, NULL), recipients, armor = armor)
  writeBin(cipher, file)
  invisible(file)
}

readRDS_age <- function(file, identities) {
  plaintext <- readBin(file, "raw", file.size(file))
  unserialize(age_decrypt_raw(plaintext, identities))
}
```

Passphrase variants should route through the `_passphrase` raw functions.

### Connections

Streaming arbitrary R connections is deferred. R connections do not expose file
descriptors, so this requires a callback-backed native I/O adapter. The existing
file API already covers constant-memory processing for large files.

### Introspection

If backend introspection is needed, prefer one `age_version()` function. There is
only one built-in backend, so availability probes and backend selectors are not
useful.

## Out of scope

- SSH-key recipients, unless the C backend gains the required stanza and key
  parsing support.
- Plugin, hardware, and post-quantum recipients.
- Runtime CLI or automatic backend selection.
- Standalone armor functions.
- An `age_ciphertext` wrapper class.
- Generic exports such as `encrypt()` or protocol-level primitives.
- An implicit secret-key accessor.

See [decisions/002-public-api-shape.md](decisions/002-public-api-shape.md) for
the consolidated API rationale.
