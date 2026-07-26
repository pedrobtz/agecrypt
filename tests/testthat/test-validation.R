# Targeted coverage of the input-validation and object-method branches: each
# test drives the smallest input that reaches a specific guard and asserts the
# typed condition (or method output) it produces.

test_that("flag and path validators reject malformed input", {
  p <- new_pair()
  # check_flag(): non-logical flag
  expect_error(
    age_encrypt_raw(charToRaw("x"), recipients = p$rec, armor = "yes"),
    class = "age_error_encrypt"
  )
  f <- withr::local_tempfile()
  writeBin(charToRaw("hi"), f)
  expect_error(
    age_encrypt_file(f, recipients = p$rec, armor = NA),
    class = "age_error_encrypt"
  )
  # check_path(): non-scalar / non-character path
  expect_error(age_keygen(path = c("a", "b")), class = "age_error_io")
  expect_error(age_keygen(path = 123), class = "age_error_io")
})

test_that("age_encrypt_raw / age_decrypt_raw reject wrong input types", {
  p <- new_pair()
  ct <- age_encrypt_raw(charToRaw("x"), recipients = p$rec)
  # x must be raw
  expect_error(
    age_encrypt_raw("not raw", recipients = p$rec),
    class = "age_error_encrypt"
  )
  # x must be raw or character
  expect_error(age_decrypt_raw(42L, identities = p$id), class = "age_error_decrypt")
  # empty / NA character
  expect_error(age_decrypt_raw(character(0), identities = p$id), class = "age_error_decrypt")
  expect_error(age_decrypt_raw(NA_character_, identities = p$id), class = "age_error_decrypt")
})

test_that("recipient and identity coercion reject bad shapes", {
  p <- new_pair()
  ct <- age_encrypt_raw(charToRaw("x"), recipients = p$rec)
  # NA in recipients
  expect_error(
    age_encrypt_raw(charToRaw("x"), recipients = c(p$rec, NA)),
    class = "age_error_recipient"
  )
  # as_age_identity(): non-character, empty, NA
  expect_error(age_decrypt_raw(ct, identities = 42L), class = "age_error_identity")
  expect_error(age_decrypt_raw(ct, identities = character(0)), class = "age_error_identity")
  expect_error(age_decrypt_raw(ct, identities = NA_character_), class = "age_error_identity")
  # collect_secret_strings(): neither an inline key nor an existing file
  expect_error(age_identity("just some words"), class = "age_error_identity")
})

test_that("key-file parsing rejects passphrase-encrypted and empty files", {
  # passphrase-encrypted key file is detected and refused
  enc <- withr::local_tempfile()
  writeLines(
    c("-----BEGIN AGE ENCRYPTED FILE-----", "abc", "-----END AGE ENCRYPTED FILE-----"),
    enc
  )
  expect_error(age_identity(enc), class = "age_error_identity")
  # a file with no identities at all
  empty <- withr::local_tempfile()
  writeLines(c("# a comment", "not a key"), empty)
  expect_error(age_identity(empty), class = "age_error_identity")
})

test_that("age_decrypt_file requires an existing input", {
  p <- new_pair()
  expect_error(
    age_decrypt_file("/no/such/file.age", identities = p$id),
    class = "age_error_io"
  )
})

test_that("identity methods: format, print-when-freed, free type check", {
  id <- age_keygen()
  # format.age_identity()
  expect_match(format(id), "age1", all = FALSE)
  # print.age_identity() "(freed)" branch
  age_identity_free(id)
  expect_output(print(id), "freed")
  # age_identity_free() type check
  expect_error(age_identity_free("not an identity"), class = "age_error_identity")
})
