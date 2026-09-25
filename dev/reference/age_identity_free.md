# Explicitly scrub an identity's secret key material

Zeroes and frees the secret bytes immediately rather than waiting for
garbage collection. The identity becomes unusable afterwards.

## Usage

``` r
age_identity_free(identity)
```

## Arguments

- identity:

  An `age_identity` object.

## Value

`invisible(NULL)`.

## Examples

``` r
id <- age_keygen()
age_identity_free(id)
```
