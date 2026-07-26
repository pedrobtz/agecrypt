#' Encrypt and decrypt files
#'
#' File-to-file encryption. Large files are streamed in constant memory in C
#' (they are not loaded into an R vector).
#'
#' @param input Path to the source file.
#' @param output Destination path. If `NULL` (default), `age_encrypt_file()`
#'   appends `.age` to `input`; `age_decrypt_file()` strips a trailing `.age`.
#'   If `input` does not end in `.age`, `age_decrypt_file()` requires `output`
#'   to be given explicitly rather than guess.
#' @param recipients Character vector of `"age1..."` recipient strings.
#' @param identities An `age_identity`, or character input accepted by
#'   [age_identity()].
#' @param armor If `TRUE`, produce ASCII-armored output.
#' @param overwrite If `FALSE` (default), error when `output` already exists.
#'
#' @return The output path, invisibly.
#' @name age_file
#' @examples
#' id <- age_keygen()
#' rec <- age_pubkey(id)
#' f <- tempfile(fileext = ".txt")
#' writeLines("hello", f)
#' enc <- age_encrypt_file(f, recipients = rec)
#' dec <- age_decrypt_file(enc, output = tempfile(), identities = id)
#' readLines(dec)
NULL

#' @rdname age_file
#' @export
age_encrypt_file <- function(input, output = NULL, recipients,
                             armor = FALSE, overwrite = FALSE) {
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
  guard_distinct_paths(input, output)
  guard_output(output, overwrite)
  recipients <- as_recipients(recipients)
  age_result(.Call(
    C_age_c_encrypt_path,
    path.expand(input), path.expand(output), recipients, armor, overwrite
  ))
  invisible(output)
}

#' @rdname age_file
#' @export
age_decrypt_file <- function(input, output = NULL, identities,
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
  id <- as_age_identity(identities)
  age_result(.Call(
    C_age_c_decrypt_path,
    path.expand(input), path.expand(output), id, overwrite
  ))
  invisible(output)
}

guard_output <- function(output, overwrite) {
  if (!overwrite && file.exists(output)) {
    age_abort("io", sprintf(
      "output already exists: %s (pass overwrite = TRUE to replace it)", output
    ))
  }
}

# Reject an output that names the same file as the input. The atomic temp-file
# write in C keeps even an undetected alias from destroying data, but rejecting
# the obvious cases up front is clearer than silently encrypting a file over
# itself.
guard_distinct_paths <- function(input, output) {
  ni <- tryCatch(
    normalizePath(input, winslash = "/", mustWork = TRUE),
    error = function(e) normalizePath(input, winslash = "/", mustWork = FALSE)
  )
  no <- normalizePath(output, winslash = "/", mustWork = FALSE)
  if (identical(ni, no)) {
    age_abort("io", "`input` and `output` must not be the same file")
  }
}
