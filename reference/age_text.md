# Encrypt and decrypt a single string

Convenience wrappers over [`age_encrypt_raw()`](age_raw.md) /
[`age_decrypt_raw()`](age_raw.md) for one string, ASCII-armored by
default so the result is copy-pasteable. Encoding is forced to UTF-8 on
the way in and marked on the way out.

## Usage

``` r
age_encrypt_text(x, recipients, armor = TRUE)

age_decrypt_text(x, identities)
```

## Arguments

- x:

  For `age_encrypt_text()`, a length-1 character string (errors on
  longer input rather than silently collapsing lines). For
  `age_decrypt_text()`, ciphertext as a raw vector or armored string.

- recipients:

  Character vector of `"age1..."` recipient strings.

- armor:

  Must be `TRUE` (the default): `age_encrypt_text()` always armors its
  output. Use [`age_encrypt_raw()`](age_raw.md) for unarmored binary
  output.

- identities:

  An `age_identity`, or character input accepted by
  [`age_identity()`](age_identity.md).

## Value

`age_encrypt_text()` returns a length-1 character string;
`age_decrypt_text()` returns a length-1 UTF-8 string.
`age_decrypt_text()` signals `age_error_decrypt` if the plaintext is not
valid UTF-8 text (for binary payloads, use
[`age_decrypt_raw()`](age_raw.md)).

## Examples

``` r
id <- age_keygen()
rec <- age_pubkey(id)
ct <- age_encrypt_text("db_password_123", recipients = rec)
age_decrypt_text(ct, identities = id)
#> [1] "db_password_123"
```
