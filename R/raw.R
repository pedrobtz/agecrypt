#' Encrypt and decrypt raw vectors
#'
#' The core buffer transforms: no file I/O, nothing written to disk. All other
#' verbs (`_file`, `_text`) build on these.
#'
#' @param x For `age_encrypt_raw()`, a raw vector of plaintext. For
#'   `age_decrypt_raw()`, a raw vector of ciphertext, or a length-1 character
#'   string of ASCII-armored ciphertext. Armor is auto-detected.
#' @param recipients Character vector of `"age1..."` recipient strings. Give
#'   several to encrypt to multiple recipients; each can decrypt.
#' @param identities An `age_identity`, or character input accepted by
#'   [age_identity()]. Tried in order; the first that matches wins.
#' @param armor If `TRUE`, produce ASCII-armored (PEM) output. The return value
#'   is still a raw vector (of the armored ASCII bytes).
#'
#' @return A raw vector: ciphertext for `age_encrypt_raw()`, plaintext for
#'   `age_decrypt_raw()`.
#' @name age_raw
#' @examples
#' id <- age_keygen()
#' rec <- age_pubkey(id)
#' ct <- age_encrypt_raw(charToRaw("hello"), recipients = rec)
#' rawToChar(age_decrypt_raw(ct, identities = id))
NULL

#' @rdname age_raw
#' @export
age_encrypt_raw <- function(x, recipients, armor = FALSE) {
  if (!is.raw(x)) {
    age_abort("encrypt", "`x` must be a raw vector")
  }
  recipients <- as_recipients(recipients)
  armor <- check_flag(armor, "armor")
  age_result(.Call(C_age_c_encrypt, x, recipients, armor))
}

#' @rdname age_raw
#' @export
age_decrypt_raw <- function(x, identities) {
  x <- as_ciphertext_raw(x)
  id <- as_age_identity(identities)
  age_result(.Call(C_age_c_decrypt, x, id))
}

as_ciphertext_raw <- function(x) {
  if (is.raw(x)) {
    return(x)
  }
  if (is.character(x)) {
    if (length(x) == 0L || anyNA(x)) {
      age_abort("decrypt", "`x` must not be empty or contain NA")
    }
    text <- paste(x, collapse = "\n")
    # Armored input must end in a newline; readLines()/copy-paste often drop
    # the final one, so restore it rather than fail on strict armor parsing.
    if (!endsWith(text, "\n")) {
      text <- paste0(text, "\n")
    }
    return(charToRaw(text))
  }
  age_abort("decrypt", "`x` must be a raw vector or a character scalar")
}
