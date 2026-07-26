# Structured errors, built with base R (no rlang dependency).
#
# Every condition inherits from "age_error", so tryCatch(age_error = ...)
# catches anything this package raises. Specific classes let callers tell
# "wrong key" (age_error_decrypt) from "bad input" (age_error_recipient) from
# a disk problem (age_error_io).

age_abort <- function(status, message, call = sys.call(-1L)) {
  class <- if (identical(status, "internal")) {
    c("age_error", "error", "condition")
  } else {
    c(paste0("age_error_", status), "age_error", "error", "condition")
  }
  stop(structure(
    class = class,
    list(message = as.character(message), call = call)
  ))
}

# Process the (status, payload) list returned by every C entry point: a
# non-empty status is turned into the matching age_error condition, otherwise
# the payload is returned. Call sites pass `.Call(C_age_c_*, ...)` directly so
# the native symbol stays literal (R CMD check can resolve the registration).
age_result <- function(res) {
  if (!identical(res[[1L]], "")) {
    age_abort(res[[1L]], res[[2L]], call = sys.call(-1L))
  }
  res[[2L]]
}

# ---- small argument validators (all raise typed conditions) ----

check_flag <- function(x, name, status = "encrypt") {
  if (!is.logical(x) || length(x) != 1L || is.na(x)) {
    age_abort(status, sprintf("`%s` must be TRUE or FALSE", name))
  }
  x
}

check_path <- function(x, name) {
  if (!is.character(x) || length(x) != 1L || is.na(x) || !nzchar(x)) {
    age_abort("io", sprintf("`%s` must be a single, non-empty file path", name))
  }
  x
}
