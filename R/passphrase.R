# Passphrase (scrypt) encryption. Kept as a separate set of verbs from the
# recipient-based functions so a call is unambiguously one mode or the other.

#' Encrypt and decrypt with a passphrase
#'
#' Passphrase-based (scrypt) encryption, a separate mode from the
#' recipient-based [age_encrypt_raw()] family. A file encrypted this way is
#' decrypted with the matching `age_decrypt_*_passphrase()` function and the
#' same passphrase — no key pair is involved.
#'
#' @param x For `age_encrypt_raw_passphrase()`, a raw vector of plaintext. For
#'   `age_decrypt_raw_passphrase()`, a raw vector of ciphertext or a length-1
#'   armored string.
#' @param input,output File paths. `output = NULL` appends/strips `.age` as in
#'   [age_encrypt_file()].
#' @param passphrase A length-1 character string. If `NULL` (the default) and
#'   the session is interactive, it is prompted for securely via
#'   `askpass::askpass()` (the suggested \pkg{askpass} package must be
#'   installed). Avoid hard-coding passphrases in scripts.
#' @param armor If `TRUE`, produce ASCII-armored output.
#' @param overwrite If `FALSE` (default), error when `output` already exists.
#' @param log_n scrypt work factor, as the base-2 logarithm of the parameter
#'   N. Higher is slower and more brute-force resistant. Defaults to 18;
#'   values above 22 are rejected (also on decrypt) to bound work.
#'
#' @return The raw functions return a raw vector; the file functions return the
#'   output path invisibly.
#' @name age_passphrase
#' @examples
#' ct <- age_encrypt_raw_passphrase(
#'   charToRaw("secret"),
#'   passphrase = "hunter2",
#'   log_n = 8
#' )
#' rawToChar(age_decrypt_raw_passphrase(ct, passphrase = "hunter2"))
NULL

#' @rdname age_passphrase
#' @export
age_encrypt_raw_passphrase <- function(x, passphrase = NULL, armor = FALSE,
                                       log_n = 18) {
  if (!is.raw(x)) {
    age_abort("encrypt", "`x` must be a raw vector")
  }
  armor <- check_flag(armor, "armor")
  log_n <- check_log_n(log_n)
  pass <- resolve_passphrase(passphrase, encrypt = TRUE)
  age_result(.Call(C_age_c_encrypt_passphrase, x, pass, armor, log_n))
}

#' @rdname age_passphrase
#' @export
age_decrypt_raw_passphrase <- function(x, passphrase = NULL) {
  x <- as_ciphertext_raw(x)
  pass <- resolve_passphrase(passphrase, encrypt = FALSE)
  age_result(.Call(C_age_c_decrypt_passphrase, x, pass))
}

#' @rdname age_passphrase
#' @export
age_encrypt_file_passphrase <- function(input, output = NULL, passphrase = NULL,
                                        armor = FALSE, overwrite = FALSE,
                                        log_n = 18) {
  input <- check_path(input, "input")
  if (!file.exists(input)) {
    age_abort("io", sprintf("input file does not exist: %s", input))
  }
  if (is.null(output)) {
    output <- paste0(input, ".age")
  }
  output <- check_path(output, "output")
  armor <- check_flag(armor, "armor")
  overwrite <- check_flag(overwrite, "overwrite", status = "io")
  log_n <- check_log_n(log_n)
  guard_distinct_paths(input, output)
  guard_output(output, overwrite)
  pass <- resolve_passphrase(passphrase, encrypt = TRUE)
  age_result(.Call(
    C_age_c_encrypt_path_passphrase,
    path.expand(input), path.expand(output), pass, armor, log_n, overwrite
  ))
  invisible(output)
}

#' @rdname age_passphrase
#' @export
age_decrypt_file_passphrase <- function(input, output = NULL, passphrase = NULL,
                                        overwrite = FALSE) {
  input <- check_path(input, "input")
  if (!file.exists(input)) {
    age_abort("io", sprintf("input file does not exist: %s", input))
  }
  if (is.null(output)) {
    output <- sub("[.]age$", "", input)
    if (identical(output, input)) {
      age_abort("io", paste(
        "cannot infer output path: input does not end in .age;",
        "pass `output` explicitly"
      ))
    }
  }
  output <- check_path(output, "output")
  overwrite <- check_flag(overwrite, "overwrite", status = "io")
  guard_distinct_paths(input, output)
  guard_output(output, overwrite)
  pass <- resolve_passphrase(passphrase, encrypt = FALSE)
  age_result(.Call(
    C_age_c_decrypt_path_passphrase,
    path.expand(input), path.expand(output), pass, overwrite
  ))
  invisible(output)
}

# ---- helpers ----

# Resolve a passphrase argument to a validated, UTF-8 length-1 string,
# prompting securely when NULL. `encrypt` only selects error class + prompt.
resolve_passphrase <- function(passphrase, encrypt) {
  status <- if (encrypt) "encrypt" else "decrypt"
  if (is.null(passphrase)) {
    if (!interactive()) {
      age_abort(status, "`passphrase` is NULL but the session is not interactive")
    }
    if (!requireNamespace("askpass", quietly = TRUE)) {
      age_abort(status, paste(
        "`passphrase` is NULL and the 'askpass' package is not installed;",
        "install it or pass `passphrase` explicitly"
      ))
    }
    prompt <- if (encrypt) "Enter passphrase to encrypt: " else "Enter passphrase: "
    passphrase <- askpass::askpass(prompt)
    if (is.null(passphrase)) {
      age_abort(status, "no passphrase supplied")
    }
  }
  if (!is.character(passphrase) || length(passphrase) != 1L || is.na(passphrase)) {
    age_abort(status, "`passphrase` must be a single string")
  }
  if (!nzchar(passphrase)) {
    age_abort(status, "`passphrase` must not be empty")
  }
  enc2utf8(passphrase)
}

check_log_n <- function(log_n) {
  if (length(log_n) != 1L || is.na(log_n) ||
    !is.numeric(log_n) || log_n != as.integer(log_n)) {
    age_abort("encrypt", "`log_n` must be a single whole number")
  }
  log_n <- as.integer(log_n)
  if (log_n < 2L || log_n > 22L) {
    age_abort("encrypt", "`log_n` must be between 2 and 22")
  }
  log_n
}
