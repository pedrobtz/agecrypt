#!/usr/bin/env Rscript
# Generate the interop test fixtures under tests/testthat/fixtures/interop/
# using the reference age implementation (FiloSottile's Go `age`) as an
# independent oracle. The produced .age files are committed so the test suite
# decrypts them OFFLINE -- no external tool is invoked at test time, which is a
# hard requirement for CRAN check machines.
#
#   Rscript tools/gen-interop-fixtures.R
#
# Requires `age` and `age-keygen` (>= v1) on PATH. The existing key.txt is
# reused, so previously committed fixtures remain valid.

suppressWarnings(pkgload::load_all(quiet = TRUE)) # our package, for the encrypt-direction check

age_bin <- unname(Sys.which("age"))
kg_bin  <- unname(Sys.which("age-keygen"))
stopifnot(
  "age not on PATH"        = nzchar(age_bin),
  "age-keygen not on PATH" = nzchar(kg_bin)
)

# Run the oracle and fail loudly, correctly attributed, on a non-zero exit
# rather than silently trusting whatever it produced.
run <- function(cmd, args) {
  st <- system2(cmd, args, stdout = FALSE, stderr = FALSE)
  if (!identical(as.integer(st), 0L)) {
    stop(sprintf("oracle failed (exit %s): %s %s", st, cmd,
      paste(args, collapse = " ")), call. = FALSE)
  }
  invisible()
}
capture <- function(cmd, args) { # capture stdout, still assert a clean exit
  out <- suppressWarnings(system2(cmd, args, stdout = TRUE))
  st <- attr(out, "status")
  if (!is.null(st) && !identical(as.integer(st), 0L)) {
    stop(sprintf("oracle failed (exit %s): %s %s", st, cmd,
      paste(args, collapse = " ")), call. = FALSE)
  }
  out
}

dir <- "tests/testthat/fixtures/interop"
sweep <- file.path(dir, "sweep")
dir.create(sweep, showWarnings = FALSE, recursive = TRUE)
key <- file.path(dir, "key.txt")
rec <- trimws(capture(kg_bin, c("-y", key))[1])

# sizes spanning below/at/above the 35-byte armor probe and the 64 KiB STREAM
# chunk boundary (70000 > 65536 => the payload spans two STREAM chunks)
sizes <- c(0L, 5L, 34L, 35L, 100L, 70000L)

# the payload for size n is strrep("A", n); the test reconstructs it from the
# file name, so no separate plaintext fixture needs to be committed.
payload <- function(n) strrep("A", n)

wrote <- 0L
for (n in sizes) {
  pf <- tempfile()
  writeBin(charToRaw(payload(n)), pf)
  for (armor in c(FALSE, TRUE)) {
    tag <- if (armor) "arm" else "bin"
    out <- file.path(sweep, sprintf("size-%d-%s.age", n, tag))
    run(age_bin, c("-e", "-r", rec, if (armor) "-a", "-o", out, pf))
    wrote <- wrote + 1L
  }
}
cat(sprintf("wrote %d decrypt-direction fixtures to %s/\n", wrote, sweep))

# --- one-time OFFLINE check of the encrypt direction ------------------------
# Reference age must accept ciphertext WE produce. This cannot become a
# committed fixture (there is nothing static to check without running age), so
# it is asserted here, now, across the same sweep -- proving our encoder is
# spec-correct against an independent implementation.
enc <- 0L
for (n in sizes) {
  msg <- payload(n)
  for (armor in c(FALSE, TRUE)) {
    ct <- age_encrypt_raw(charToRaw(msg), recipients = rec, armor = armor)
    cf <- tempfile()
    writeBin(ct, cf)
    back <- capture(age_bin, c("-d", "-i", key, cf))
    if (!identical(paste(back, collapse = "\n"), msg)) {
      stop(sprintf("encrypt-direction interop FAILED (n=%d armor=%s)", n, armor),
        call. = FALSE)
    }
    enc <- enc + 1L
  }
}
ver <- sub("^v", "", capture(age_bin, "--version")[1])
cat(sprintf("encrypt-direction: %d/%d checks passed against reference age v%s\n",
  enc, enc, ver))
