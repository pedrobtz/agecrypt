# Derive public recipient strings from identities

Derive public recipient strings from identities

## Usage

``` r
age_pubkey(identities)
```

## Arguments

- identities:

  An `age_identity`, or character input accepted by
  [`age_identity()`](age_identity.md) (inline secret keys and/or
  key-file paths).

## Value

A character vector of `"age1..."` recipient strings, one per identity.

## Examples

``` r
id <- age_keygen()
age_pubkey(id)
#> [1] "age1c2l5gfk8w426k4mgnmagk7rr03272cw27tzjg2233n2sewe5nf7skuft4d"
```
