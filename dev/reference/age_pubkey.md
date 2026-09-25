# Derive public recipient strings from identities

Derive public recipient strings from identities

## Usage

``` r
age_pubkey(identities)
```

## Arguments

- identities:

  An `age_identity`, or character input accepted by
  [`age_identity()`](https://pedrobtz.github.io/agecrypt/dev/reference/age_identity.md)
  (inline secret keys and/or key-file paths).

## Value

A character vector of `"age1..."` recipient strings, one per identity.

## Examples

``` r
id <- age_keygen()
age_pubkey(id)
#> [1] "age1sqj3s2pkx8n9u3n7c0dqcvp20g2zr9phqz0ejsdjnnz60zkqm4fqps7zrw"
```
