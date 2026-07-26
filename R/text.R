#' Encrypt and decrypt a single string
#'
#' Convenience wrappers over [age_encrypt_raw()] / [age_decrypt_raw()] for one
#' string, ASCII-armored by default so the result is copy-pasteable. Encoding
#' is forced to UTF-8 on the way in and marked on the way out.
#'
#' @param x For `age_encrypt_text()`, a length-1 character string (errors on
#'   longer input rather than silently collapsing lines). For
#'   `age_decrypt_text()`, ciphertext as a raw vector or armored string.
#' @param recipients Character vector of `"age1..."` recipient strings.
#' @param identities An `age_identity`, or character input accepted by
#'   [age_identity()].
#' @param armor Must be `TRUE` (the default): `age_encrypt_text()` always
#'   armors its output. Use [age_encrypt_raw()] for unarmored binary output.
#'
#' @return `age_encrypt_text()` returns a length-1 character string;
#'   `age_decrypt_text()` returns a length-1 UTF-8 string. `age_decrypt_text()`
#'   signals `age_error_decrypt` if the plaintext is not valid UTF-8 text (for
#'   binary payloads, use [age_decrypt_raw()]).
#' @name age_text
#' @examples
#' id <- age_keygen()
#' rec <- age_pubkey(id)
#' ct <- age_encrypt_text("db_password_123", recipients = rec)
#' age_decrypt_text(ct, identities = id)
NULL

#' @rdname age_text
#' @export
age_encrypt_text <- function(x, recipients, armor = TRUE) {
  if (!is.character(x) || length(x) != 1L) {
    age_abort("encrypt", "`x` must be a length-1 character string")
  }
  if (is.na(x)) {
    age_abort("encrypt", "`x` must not be NA")
  }
  armor <- check_flag(armor, "armor")
  if (!armor) {
    age_abort("encrypt", paste(
      "`age_encrypt_text()` always produces armored text;",
      "use `age_encrypt_raw()` for unarmored binary output"
    ))
  }
  ct <- age_encrypt_raw(charToRaw(enc2utf8(x)), recipients = recipients,
                        armor = TRUE)
  rawToChar(ct)
}

#' @rdname age_text
#' @export
age_decrypt_text <- function(x, identities) {
  raw <- age_decrypt_raw(x, identities = identities)
  # age_decrypt_text is for text; refuse to hand back binary as a bogus string.
  if (length(raw) > 0L && any(raw == as.raw(0L))) {
    age_abort("decrypt", paste(
      "decrypted data contains an embedded NUL;",
      "use age_decrypt_raw() for binary data"
    ))
  }
  out <- rawToChar(raw)
  if (!validUTF8(out)) {
    age_abort("decrypt", paste(
      "decrypted data is not valid UTF-8;",
      "use age_decrypt_raw() for binary data"
    ))
  }
  Encoding(out) <- "UTF-8"
  out
}
