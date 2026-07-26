# agecrypt

<!-- badges: start -->
[![R-CMD-check](https://github.com/pedrobtz/agecrypt/actions/workflows/R-CMD-check.yaml/badge.svg)](https://github.com/pedrobtz/agecrypt/actions/workflows/R-CMD-check.yaml)
[![coverage](https://raw.githubusercontent.com/pedrobtz/agecrypt/main/.github/badges/coverage.svg)](https://github.com/pedrobtz/agecrypt/actions/workflows/coverage.yaml)
[![Lifecycle: experimental](https://img.shields.io/badge/lifecycle-experimental-orange.svg)](https://lifecycle.r-lib.org/articles/stages.html#experimental)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
<!-- badges: end -->

An idiomatic R interface to the [**age**](https://age-encryption.org/v1) file
encryption format. Encrypt and decrypt raw vectors, files, and strings — to
public-key recipients or with a passphrase — with optional ASCII armor.

The cryptography is a vendored copy of the C implementation
[`agec`](https://git.sr.ht/~min/agec), and randomness comes from the operating
system, so **the package has no external
library dependencies** (no OpenSSL, no Go or Rust toolchain, no `age` binary to
install). Files it produces interoperate with the reference
[`age`](https://github.com/FiloSottile/age) implementation in both directions.

## Installation

Install the development version from GitHub:

``` r
# install.packages("pak")
pak::pak("pedrobtz/agecrypt")
```

Once released on CRAN:

``` r
install.packages("agecrypt")
```

Either way there is nothing else to install — no system libraries and no
external programs.

## The mental model

age has two kinds of keys, and this package keeps that vocabulary:

- a **recipient** is a public key (`age1…`) you **encrypt** to;
- an **identity** is the matching secret key (`AGE-SECRET-KEY-1…`) you
  **decrypt** with.

``` r
library(agecrypt)

id  <- age_keygen()      # a new identity (keypair)
rec <- age_pubkey(id)    # its recipient (public) string

id
#> <age_identity>
#>   public key: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
```

The secret key of a *generated* identity is created in C and kept there — the
`age_identity` object never exposes it, and its print method shows only the
public key. (Identities you supply yourself, as `AGE-SECRET-KEY-1…` strings or
key files, unavoidably exist in R since you pass them in.)

## Encrypting and decrypting

Three I/O shapes, all following the same `recipients =` / `identities =`
pattern.

### Raw vectors (in memory, nothing touches disk)

``` r
ct <- age_encrypt_raw(charToRaw("hello world"), recipients = rec)
rawToChar(age_decrypt_raw(ct, identities = id))
#> [1] "hello world"
```

Ideal for secrets pulled from a vault or object store and decrypted without
ever writing plaintext to disk:

``` r
creds <- readBin("secrets.yaml.age", "raw", 1e6) |>
  age_decrypt_raw(identities = id) |>
  rawToChar() |>
  yaml::yaml.load()
```

### Files (streamed in constant memory)

``` r
age_encrypt_file("data.csv", recipients = rec)     # writes data.csv.age
age_decrypt_file("data.csv.age", identities = id)  # writes data.csv
```

Large files are streamed chunk by chunk in C, so a multi-gigabyte file is never
loaded into an R vector. Existing outputs are not overwritten unless you pass
`overwrite = TRUE`.

### Strings (ASCII-armored, copy-pasteable)

``` r
ct <- age_encrypt_text("db_password_123", recipients = rec)
cat(ct)
#> -----BEGIN AGE ENCRYPTED FILE-----
#> ...
#> -----END AGE ENCRYPTED FILE-----

age_decrypt_text(ct, identities = id)
#> [1] "db_password_123"
```

`age_encrypt_text()` is armored by default so the result pastes cleanly into a
chat message, a commit, or an `.Renviron`.

## Multiple recipients

Encrypt once, and each recipient can decrypt with their own identity:

``` r
age_encrypt_file(
  "backup.tar",
  recipients = c(
    "age1alice…",
    "age1bob…",
    "age1backup…"
  )
)
```

## Key files and identities

Write a key to disk in the standard age key-file format:

``` r
age_keygen("~/.config/age/key.txt")
```

Anywhere an `identities =` argument appears, you can pass an `age_identity`
object, an inline `"AGE-SECRET-KEY-1…"` string, or a path to a key file — it is
auto-detected per element:

``` r
age_decrypt_file("data.csv.age", identities = "~/.config/age/key.txt")
age_decrypt_raw(ct, identities = Sys.getenv("AGE_KEY"))  # inline, no file
```

You can also keep the identity in the OS keychain via the optional
[`keyring`](https://cran.r-project.org/package=keyring) package:

``` r
secret <- readLines("~/.config/age/key.txt")
secret <- secret[startsWith(secret, "AGE-SECRET-KEY-1")]
keyring::key_set_with_value("agecrypt", "default", secret)

age_decrypt_file("data.csv.age",
  identities = keyring::key_get("agecrypt", "default"))
```

A key file may hold several identities; decryption tries each until one
matches.

## Passphrase encryption

A separate set of verbs (never a `passphrase =` flag on the recipient-based
functions, to keep each call unambiguously one mode):

``` r
ct <- age_encrypt_raw_passphrase(charToRaw("secret"), passphrase = "correct horse")
rawToChar(age_decrypt_raw_passphrase(ct, passphrase = "correct horse"))
#> [1] "secret"

age_encrypt_file_passphrase("notes.txt")     # prompts securely (via askpass)
age_decrypt_file_passphrase("notes.txt.age")
```

If `passphrase = NULL` and the session is interactive, you are prompted
securely via [`askpass`](https://cran.r-project.org/package=askpass). The
scrypt work factor is a plain `log_n` argument (default `18`).

## Error handling

Failures are signalled with typed conditions, all inheriting from `age_error`,
so batch callers can tell a wrong key from corrupt ciphertext from a disk
problem:

| Condition class | Raised when |
|---|---|
| `age_error_recipient` | a recipient string fails to parse |
| `age_error_identity`  | an identity string or key file fails to parse |
| `age_error_encrypt`   | encryption fails after inputs are valid |
| `age_error_decrypt`   | no identity/passphrase matches, or authentication fails |
| `age_error_io`        | a file cannot be read or written |

``` r
tryCatch(
  age_decrypt_file("data.csv.age", identities = id),
  age_error_decrypt  = function(e) log_and_retry(e),
  age_error_identity = function(e) stop("misconfigured key", call. = FALSE)
)
```

## Function reference

| | Public key (recipients) | Passphrase |
|---|---|---|
| **raw** | `age_encrypt_raw()` / `age_decrypt_raw()` | `age_encrypt_raw_passphrase()` / `age_decrypt_raw_passphrase()` |
| **file** | `age_encrypt_file()` / `age_decrypt_file()` | `age_encrypt_file_passphrase()` / `age_decrypt_file_passphrase()` |
| **text** | `age_encrypt_text()` / `age_decrypt_text()` | — |
| **keys** | `age_keygen()`, `age_pubkey()`, `age_identity()`, `age_identity_free()` | |

## How it works, and why you can trust it

- **Spec-compliant.** Passes the official
  [C2SP CCTV](https://github.com/C2SP/CCTV/tree/main/age) age test vectors
  (both X25519 and scrypt) — known answers decrypt correctly and malformed
  inputs are rejected.
- **Interoperable.** Reference `age` CLI fixtures are exercised by the test
  suite, and reverse interoperability is checked when those fixtures are
  generated.
- **Self-contained.** ChaCha20-Poly1305, X25519, HKDF, scrypt and SHA-256 are
  all vendored; the only OS-specific code is the random-bytes call
  (`getentropy` / `arc4random_buf` / `BCryptGenRandom`).
- **Careful with secrets.** An identity's secret bytes are held in C behind an
  opaque pointer, zeroed by a finalizer, and never printed or returned to R by
  the `age_identity` object. Secrets and passphrases you pass in as strings, or
  read from a key file, necessarily live in R for their normal lifetime — the
  package does not (and cannot) hide those.

## Scope

Supported: X25519 recipients, scrypt passphrases, and ASCII armor — the full
age v1 format for the common cases.

Not currently supported: SSH-key recipients (`ssh-ed25519 …`), and plugin /
hardware / post-quantum recipients. These would require new stanza types in the
C backend rather than R glue.

Concurrency: encryption and decryption must run on R's main thread, one
operation at a time — the usual way R calls compiled code. The C backend keeps
some process-global state, so the functions are not reentrant and must not be
called from multiple threads in parallel (e.g. a threaded worker pool). Normal
sequential use is unaffected.

## See also

- The [age specification](https://age-encryption.org/v1)
- The reference [`age`](https://github.com/FiloSottile/age) CLI
- [`awesome-age`](https://github.com/FiloSottile/awesome-age) — other
  implementations and tools

## License

MIT © the agecrypt authors. The vendored `agec` C sources are distributed
under the 0BSD license; see `inst/COPYRIGHTS`.
