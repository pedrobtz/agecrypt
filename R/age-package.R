#' agecrypt: File Encryption with the age Format
#'
#' A dependency-free implementation of the
#' \href{https://age-encryption.org/v1}{age} v1 file encryption format,
#' backed by a vendored copy of the C implementation \code{agec}. Encrypts to
#' one or more X25519 recipients or with a passphrase, with optional ASCII
#' armor. SSH-key recipients and plugins are not supported.
#'
#' @keywords internal
#' @useDynLib agecrypt, .registration = TRUE, .fixes = "C_"
"_PACKAGE"
