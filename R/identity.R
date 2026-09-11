# The age_identity object wraps an opaque external pointer holding one or more
# X25519 private keys as a single C-side array. Secret bytes never surface in
# R: there is no accessor and the print method shows only public keys. The C
# finalizer scrubs the key bytes before freeing.

new_age_identity <- function(ptr) {
  structure(ptr, class = "age_identity")
}

#' Generate a new age identity
#'
#' Creates a fresh X25519 identity (key pair). The secret key is generated in C
#' and never returned to R; to persist it, pass `path` so it is written
#' directly to a key file in the standard age format.
#'
#' @param path Optional file path. If given, the identity is written as a key
#'   file (`# created:` / `# public key:` / `AGE-SECRET-KEY-1...`) and the
#'   object is returned invisibly. If `NULL` (default), nothing is written.
#' @param overwrite If `FALSE` (default) and `path` already exists, error
#'   rather than clobbering an existing key.
#'
#' @return An `age_identity` object. Its print method shows only the public
#'   key; the secret is never printed.
#' @export
#' @examples
#' id <- age_keygen()
#' id
#' age_pubkey(id)
age_keygen <- function(path = NULL, overwrite = FALSE) {
  ptr <- age_result(.Call(C_age_c_keygen))
  id <- new_age_identity(ptr)
  if (!is.null(path)) {
    path <- check_path(path, "path")
    overwrite <- check_flag(overwrite, "overwrite", status = "io")
    if (!overwrite && file.exists(path)) {
      age_abort(
        "io",
        sprintf(
          "file already exists: %s (pass overwrite = TRUE to replace it)",
          path
        )
      )
    }
    created <- format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC")
    age_result(.Call(
      C_age_c_identity_write,
      ptr,
      path.expand(path),
      created,
      overwrite
    ))
    return(invisible(id))
  }
  id
}

#' Parse or load age identities
#'
#' @param x A character vector of inline `"AGE-SECRET-KEY-1..."` secret-key
#'   strings and/or paths to (plaintext) key files. Auto-detected per element.
#'   An `age_identity` is returned unchanged.
#' @return An `age_identity` object.
#' @export
#' @examples
#' id <- age_keygen()
#' # round-trip through a key file
#' f <- tempfile()
#' age_keygen(f)
#' id2 <- age_identity(f)
age_identity <- function(x) {
  as_age_identity(x)
}

#' Derive public recipient strings from identities
#'
#' @param identities An `age_identity`, or character input accepted by
#'   [age_identity()] (inline secret keys and/or key-file paths).
#' @return A character vector of `"age1..."` recipient strings, one per
#'   identity.
#' @export
#' @examples
#' id <- age_keygen()
#' age_pubkey(id)
age_pubkey <- function(identities) {
  id <- as_age_identity(identities)
  age_result(.Call(C_age_c_identity_pubkeys, id))
}

#' Explicitly scrub an identity's secret key material
#'
#' Zeroes and frees the secret bytes immediately rather than waiting for
#' garbage collection. The identity becomes unusable afterwards.
#'
#' @param identity An `age_identity` object.
#' @return `invisible(NULL)`.
#' @export
#' @examples
#' id <- age_keygen()
#' age_identity_free(id)
age_identity_free <- function(identity) {
  if (!inherits(identity, "age_identity")) {
    age_abort("identity", "`identity` must be an age_identity object")
  }
  .Call(C_age_c_identity_free, identity)
  invisible(NULL)
}

#' @export
print.age_identity <- function(x, ...) {
  keys <- tryCatch(
    age_result(.Call(C_age_c_identity_pubkeys, x)),
    age_error = function(e) character()
  )
  cat("<age_identity>\n")
  if (length(keys) == 0) {
    cat("  (freed)\n")
  } else {
    for (k in keys) {
      cat("  public key:", k, "\n")
    }
  }
  invisible(x)
}

#' @export
format.age_identity <- function(x, ...) {
  keys <- age_result(.Call(C_age_c_identity_pubkeys, x))
  c("<age_identity>", paste0("  public key: ", keys))
}

# ---- internal input coercion ----

as_age_identity <- function(x) {
  if (inherits(x, "age_identity")) {
    return(x)
  }
  if (!is.character(x)) {
    age_abort(
      "identity",
      "`identities` must be an age_identity or a character vector"
    )
  }
  if (length(x) == 0L || anyNA(x)) {
    age_abort("identity", "`identities` must not be empty or contain NA")
  }
  # Classify each element, then let C do the reading. Secrets loaded from a
  # key file must never become R strings: R interns every string in a global
  # cache that is effectively never released, so an "AGE-SECRET-KEY-1..." line
  # read with readLines() would sit in the session's memory in plaintext for
  # as long as the process lives. Only the *paths* cross into C here.
  inline <- startsWith(x, "AGE-SECRET-KEY-1")
  is_file <- !inline & file.exists(x)
  bad <- which(!inline & !is_file)
  if (length(bad) > 0L) {
    age_abort(
      "identity",
      sprintf(
        "not an inline secret key or an existing key file: %s",
        x[bad[1L]]
      )
    )
  }
  x[is_file] <- path.expand(x[is_file])
  new_age_identity(age_result(
    .Call(C_age_c_identity_parse, x, is_file)
  ))
}
