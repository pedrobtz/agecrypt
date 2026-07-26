# Generate a new age identity

Creates a fresh X25519 identity (key pair). The secret key is generated
in C and never returned to R; to persist it, pass `path` so it is
written directly to a key file in the standard age format.

## Usage

``` r
age_keygen(path = NULL, overwrite = FALSE)
```

## Arguments

- path:

  Optional file path. If given, the identity is written as a key file
  (`# created:` / `# public key:` / `AGE-SECRET-KEY-1...`) and the
  object is returned invisibly. If `NULL` (default), nothing is written.

- overwrite:

  If `FALSE` (default) and `path` already exists, error rather than
  clobbering an existing key.

## Value

An `age_identity` object. Its print method shows only the public key;
the secret is never printed.

## Examples

``` r
id <- age_keygen()
id
#> <age_identity>
#>   public key: age1v99pwz3dfd5fqkfk86cwrvyrkkpaawk2r3dc24e8z9uatl68ksgqvdfjcq 
age_pubkey(id)
#> [1] "age1v99pwz3dfd5fqkfk86cwrvyrkkpaawk2r3dc24e8z9uatl68ksgqvdfjcq"
```
