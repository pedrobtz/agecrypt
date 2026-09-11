# Regression tests for the native binding hardening pass.
#
# Several of these call the registered symbols directly. That is not how the
# package is used, but the invariant is that C never crashes, leaks, or reaches
# undefined behaviour on bad input -- the R layer is defence in depth, not the
# only guard -- so the entry points are exercised without it here.

test_that("key files with many identities are read in order", {
  kf1 <- withr::local_tempfile()
  kf2 <- withr::local_tempfile()
  age_keygen(kf1)
  age_keygen(kf2)
  combined <- withr::local_tempfile()
  writeLines(c(readLines(kf1), readLines(kf2)), combined)

  keys <- age_pubkey(age_identity(combined))
  expect_length(keys, 2L)
  expect_identical(keys[1], age_pubkey(age_identity(kf1)))
  expect_identical(keys[2], age_pubkey(age_identity(kf2)))
})

test_that("inline keys and key-file paths can be mixed, keeping order", {
  kf <- withr::local_tempfile()
  age_keygen(kf)
  other <- age_keygen()
  secret <- grep("^AGE-SECRET-KEY-1", readLines(kf), value = TRUE)

  # inline first, then the same key via its file: two entries, both valid
  keys <- age_pubkey(age_identity(c(secret, kf)))
  expect_length(keys, 2L)
  expect_true(all(keys == age_pubkey(age_identity(kf))))
  expect_no_match(keys, "^$")
  expect_false(any(keys == age_pubkey(other)))
})

test_that("the C key-file reader tolerates CRLF and trailing whitespace", {
  kf <- withr::local_tempfile()
  age_keygen(kf)
  expected <- age_pubkey(age_identity(kf))

  crlf <- withr::local_tempfile()
  writeBin(
    charToRaw(paste0(paste(readLines(kf), collapse = "\r\n"), "  \r\n")),
    crlf
  )
  expect_identical(age_pubkey(age_identity(crlf)), expected)
})

test_that("the C key-file reader rejects malformed and oversized files", {
  # a line that looks like a key but does not decode
  bad <- withr::local_tempfile()
  writeLines("AGE-SECRET-KEY-1NOTAVALIDKEYNOTAVALIDKEY", bad)
  expect_error(age_identity(bad), class = "age_error_identity")

  # Refuse to slurp something enormous rather than reading it all. The valid
  # key comes first, so without the cap this file would parse successfully --
  # the error can only come from the size limit.
  kf <- withr::local_tempfile()
  age_keygen(kf)
  big <- withr::local_tempfile()
  writeLines(c(readLines(kf), strrep("#", 2e6)), big)
  expect_error(age_identity(big), class = "age_error_identity")
  expect_error(age_identity(big), "too large")
})

test_that("key-file secrets are not read into R strings", {
  # Secrets loaded from disk must stay in C: R interns every string it creates
  # in a global cache that is effectively never released, so reading a key file
  # with readLines() would leave the secret in session memory for the life of
  # the process. Lock the invariant at the only place that could regress.
  src <- paste(deparse(as_age_identity), collapse = " ")
  expect_no_match(src, "readLines")
  expect_no_match(src, "readBin")
  expect_false(exists("read_keyfile_secrets", envir = asNamespace("agecrypt")))

  # and the functional behaviour still works
  kf <- withr::local_tempfile()
  age_keygen(kf)
  expect_match(age_pubkey(age_identity(kf)), "^age1")
})

test_that("the scrypt work factor is bounded in C, not only in R", {
  # agec computes `1 << cost` on an int, so an out-of-range cost reaching the
  # backend is undefined behaviour. The R layer checks first; C must too.
  for (bad in list(NA_integer_, 0L, 1L, 23L, 99L, .Machine$integer.max)) {
    res <- .Call(C_age_c_encrypt_passphrase, charToRaw("x"), "pw", FALSE, bad)
    expect_identical(res[[1L]], "encrypt")
    expect_match(res[[2L]], "work factor out of range")
  }
  # an in-range factor still works
  res <- .Call(C_age_c_encrypt_passphrase, charToRaw("x"), "pw", FALSE, 8L)
  expect_identical(res[[1L]], "")
  expect_type(res[[2L]], "raw")
})

test_that("the file passphrase entry point bounds the work factor too", {
  f <- withr::local_tempfile()
  writeBin(charToRaw("x"), f)
  res <- .Call(
    C_age_c_encrypt_path_passphrase,
    f, withr::local_tempfile(), "pw", FALSE, 99L, FALSE
  )
  expect_identical(res[[1L]], "encrypt")
  expect_match(res[[2L]], "work factor out of range")
})

test_that("recipient parsing type-checks before allocating", {
  # STRING_ELT() on a non-character vector raises an R error; if that happened
  # after the recipient array was malloc'd, the longjmp would leak it.
  res <- .Call(C_age_c_encrypt, charToRaw("x"), 1L, FALSE)
  expect_identical(res[[1L]], "recipient")
  expect_match(res[[2L]], "character vector")

  res <- .Call(C_age_c_encrypt, charToRaw("x"), NA_character_, FALSE)
  expect_identical(res[[1L]], "recipient")

  res <- .Call(C_age_c_encrypt, charToRaw("x"), character(0), FALSE)
  expect_identical(res[[1L]], "recipient")
})

test_that("identity parsing type-checks its arguments", {
  expect_identical(.Call(C_age_c_identity_parse, 1L, TRUE)[[1L]], "identity")
  expect_identical(.Call(C_age_c_identity_parse, "x", "x")[[1L]], "identity")
  # mismatched lengths must not read past the logical vector
  expect_identical(
    .Call(C_age_c_identity_parse, c("a", "b"), TRUE)[[1L]],
    "identity"
  )
  expect_identical(
    .Call(C_age_c_identity_parse, character(0), logical(0))[[1L]],
    "identity"
  )
  expect_identical(
    .Call(C_age_c_identity_parse, NA_character_, FALSE)[[1L]],
    "identity"
  )
})

test_that("repeated failures do not exhaust the in-memory stream table", {
  # memtab holds only MEMFD_MAX slots. A slot leaked on an error path would
  # wedge the backend after a handful of failures, so hammer the error paths
  # and confirm the next real operation still works.
  p <- new_pair()
  ct <- age_encrypt_raw(charToRaw("canary"), recipients = p$rec)
  other <- age_keygen()
  for (i in seq_len(50)) {
    expect_error(
      age_decrypt_raw(ct, identities = other),
      class = "age_error_decrypt"
    )
    expect_error(
      age_decrypt_raw(as.raw(c(1, 2, 3)), identities = p$id),
      class = "age_error_decrypt"
    )
  }
  expect_identical(rawToChar(age_decrypt_raw(ct, identities = p$id)), "canary")
})

test_that("each failure reports its own cause, not a stale one", {
  # agec keeps one process-global message buffer that it never clears; every
  # entry point resets it so a message cannot survive into the next operation.
  p <- new_pair()
  ct <- age_encrypt_raw(charToRaw("x"), recipients = p$rec)

  m_decrypt <- tryCatch(
    age_decrypt_raw(ct, identities = age_keygen()),
    age_error = conditionMessage
  )
  m_garbage <- tryCatch(
    age_decrypt_raw(as.raw(c(0xff, 0x00, 0x11)), identities = p$id),
    age_error = conditionMessage
  )
  m_again <- tryCatch(
    age_decrypt_raw(ct, identities = age_keygen()),
    age_error = conditionMessage
  )

  expect_false(identical(m_decrypt, m_garbage))
  # the same failure reports the same thing regardless of what preceded it
  expect_identical(m_decrypt, m_again)
})
