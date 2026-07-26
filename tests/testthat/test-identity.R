test_that("age_keygen returns an identity whose print hides the secret", {
  id <- age_keygen()
  expect_s3_class(id, "age_identity")
  out <- paste(capture.output(print(id)), collapse = "\n")
  expect_match(out, "public key: age1")
  expect_no_match(out, "AGE-SECRET-KEY")
})

test_that("age_pubkey is a 62-char age1 string and is deterministic", {
  id <- age_keygen()
  rec <- age_pubkey(id)
  expect_type(rec, "character")
  expect_length(rec, 1L)
  expect_match(rec, "^age1[0-9a-z]{58}$")
  expect_identical(age_pubkey(id), rec)
})

test_that("age_keygen(path) writes a readable key file and honours overwrite", {
  kf <- withr::local_tempfile()
  id <- age_keygen(kf)
  expect_true(file.exists(kf))
  lines <- readLines(kf)
  expect_true(any(startsWith(lines, "# public key: age1")))
  expect_true(any(startsWith(lines, "AGE-SECRET-KEY-1")))

  # same public key when re-read from disk
  expect_identical(age_pubkey(age_identity(kf)), age_pubkey(id))

  # refuses to clobber unless overwrite = TRUE
  expect_error(age_keygen(kf), class = "age_error_io")
  expect_silent(age_keygen(kf, overwrite = TRUE))
})

test_that("age_identity accepts inline secret keys and existing files", {
  kf <- withr::local_tempfile()
  age_keygen(kf)
  secret <- grep("^AGE-SECRET-KEY-1", readLines(kf), value = TRUE)

  from_inline <- age_identity(secret)
  from_file <- age_identity(kf)
  expect_identical(age_pubkey(from_inline), age_pubkey(from_file))
})

test_that("age_identity_free scrubs the key and later use errors", {
  id <- age_keygen()
  rec <- age_pubkey(id)
  ct <- age_encrypt_raw(charToRaw("z"), recipients = rec)
  expect_null(age_identity_free(id))
  expect_error(age_decrypt_raw(ct, identities = id), class = "age_error_identity")
})
