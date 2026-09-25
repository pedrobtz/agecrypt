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
#> [1] "age12vcz35lum8puyjfm5uxvm5y3exd6pt8nzmkpf5xem282uy8yk9xszuefwy"
```
