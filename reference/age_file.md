# Encrypt and decrypt files

File-to-file encryption. Large files are streamed in constant memory in
C (they are not loaded into an R vector).

## Usage

``` r
age_encrypt_file(
  input,
  output = NULL,
  recipients,
  armor = FALSE,
  overwrite = FALSE
)

age_decrypt_file(input, output = NULL, identities, overwrite = FALSE)
```

## Arguments

- input:

  Path to the source file.

- output:

  Destination path. If `NULL` (default), `age_encrypt_file()` appends
  `.age` to `input`; `age_decrypt_file()` strips a trailing `.age`. If
  `input` does not end in `.age`, `age_decrypt_file()` requires `output`
  to be given explicitly rather than guess.

- recipients:

  Character vector of `"age1..."` recipient strings.

- armor:

  If `TRUE`, produce ASCII-armored output.

- overwrite:

  If `FALSE` (default), error when `output` already exists.

- identities:

  An `age_identity`, or character input accepted by
  [`age_identity()`](age_identity.md).

## Value

The output path, invisibly.

## Examples

``` r
id <- age_keygen()
rec <- age_pubkey(id)
f <- tempfile(fileext = ".txt")
writeLines("hello", f)
enc <- age_encrypt_file(f, recipients = rec)
dec <- age_decrypt_file(enc, output = tempfile(), identities = id)
readLines(dec)
#> [1] "hello"
```
