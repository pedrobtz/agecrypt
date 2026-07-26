# Encrypt and decrypt raw vectors

The core buffer transforms: no file I/O, nothing written to disk. All
other verbs (`_file`, `_text`) build on these.

## Usage

``` r
age_encrypt_raw(x, recipients, armor = FALSE)

age_decrypt_raw(x, identities)
```

## Arguments

- x:

  For `age_encrypt_raw()`, a raw vector of plaintext. For
  `age_decrypt_raw()`, a raw vector of ciphertext, or a length-1
  character string of ASCII-armored ciphertext. Armor is auto-detected.

- recipients:

  Character vector of `"age1..."` recipient strings. Give several to
  encrypt to multiple recipients; each can decrypt.

- armor:

  If `TRUE`, produce ASCII-armored (PEM) output. The return value is
  still a raw vector (of the armored ASCII bytes).

- identities:

  An `age_identity`, or character input accepted by
  [`age_identity()`](age_identity.md). Tried in order; the first that
  matches wins.

## Value

A raw vector: ciphertext for `age_encrypt_raw()`, plaintext for
`age_decrypt_raw()`.

## Examples

``` r
id <- age_keygen()
rec <- age_pubkey(id)
ct <- age_encrypt_raw(charToRaw("hello"), recipients = rec)
rawToChar(age_decrypt_raw(ct, identities = id))
#> [1] "hello"
```
