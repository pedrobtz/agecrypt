# Parse or load age identities

Parse or load age identities

## Usage

``` r
age_identity(x)
```

## Arguments

- x:

  A character vector of inline `"AGE-SECRET-KEY-1..."` secret-key
  strings and/or paths to (plaintext) key files. Auto-detected per
  element. An `age_identity` is returned unchanged.

## Value

An `age_identity` object.

## Examples

``` r
id <- age_keygen()
# round-trip through a key file
f <- tempfile()
age_keygen(f)
id2 <- age_identity(f)
```
