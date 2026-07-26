# Encrypt and decrypt with a passphrase

Passphrase-based (scrypt) encryption, a separate mode from the
recipient-based [`age_encrypt_raw()`](age_raw.md) family. A file
encrypted this way is decrypted with the matching
`age_decrypt_*_passphrase()` function and the same passphrase — no key
pair is involved.

## Usage

``` r
age_encrypt_raw_passphrase(x, passphrase = NULL, armor = FALSE, log_n = 18)

age_decrypt_raw_passphrase(x, passphrase = NULL)

age_encrypt_file_passphrase(
  input,
  output = NULL,
  passphrase = NULL,
  armor = FALSE,
  overwrite = FALSE,
  log_n = 18
)

age_decrypt_file_passphrase(
  input,
  output = NULL,
  passphrase = NULL,
  overwrite = FALSE
)
```

## Arguments

- x:

  For `age_encrypt_raw_passphrase()`, a raw vector of plaintext. For
  `age_decrypt_raw_passphrase()`, a raw vector of ciphertext or a
  length-1 armored string.

- passphrase:

  A length-1 character string. If `NULL` (the default) and the session
  is interactive, it is prompted for securely via
  [`askpass::askpass()`](https://r-lib.r-universe.dev/askpass/reference/askpass.html)
  (the suggested askpass package must be installed). Avoid hard-coding
  passphrases in scripts.

- armor:

  If `TRUE`, produce ASCII-armored output.

- log_n:

  scrypt work factor, as the base-2 logarithm of the parameter N. Higher
  is slower and more brute-force resistant. Defaults to 18; values above
  22 are rejected (also on decrypt) to bound work.

- input, output:

  File paths. `output = NULL` appends/strips `.age` as in
  [`age_encrypt_file()`](age_file.md).

- overwrite:

  If `FALSE` (default), error when `output` already exists.

## Value

The raw functions return a raw vector; the file functions return the
output path invisibly.

## Examples

``` r
ct <- age_encrypt_raw_passphrase(
  charToRaw("secret"),
  passphrase = "hunter2",
  log_n = 8
)
rawToChar(age_decrypt_raw_passphrase(ct, passphrase = "hunter2"))
#> [1] "secret"
```
