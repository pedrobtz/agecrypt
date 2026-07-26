test_that("recipient problems raise age_error_recipient", {
  id <- age_keygen()
  expect_error(
    age_encrypt_raw(charToRaw("x"), recipients = "age1notreal"),
    class = "age_error_recipient"
  )
  # an identity object is not a valid recipient
  expect_error(
    age_encrypt_raw(charToRaw("x"), recipients = id),
    class = "age_error_recipient"
  )
  expect_error(
    age_encrypt_raw(charToRaw("x"), recipients = character()),
    class = "age_error_recipient"
  )
})

test_that("identity problems raise age_error_identity", {
  p <- new_pair()
  ct <- age_encrypt_raw(charToRaw("x"), recipients = p$rec)
  expect_error(
    age_decrypt_raw(ct, identities = "AGE-SECRET-KEY-1BOGUS"),
    class = "age_error_identity"
  )
  expect_error(
    age_decrypt_raw(ct, identities = "/no/such/key/file"),
    class = "age_error_identity"
  )
})

test_that("undecryptable input raises age_error_decrypt", {
  p <- new_pair()
  ct <- age_encrypt_raw(charToRaw("secret"), recipients = p$rec)

  # wrong identity
  expect_error(
    age_decrypt_raw(ct, identities = age_keygen()),
    class = "age_error_decrypt"
  )
  # garbage
  expect_error(
    age_decrypt_raw(as.raw(1:8), identities = p$id),
    class = "age_error_decrypt"
  )
  # truncated
  expect_error(
    age_decrypt_raw(ct[seq_len(length(ct) - 1L)], identities = p$id),
    class = "age_error_decrypt"
  )
  # tampered final byte fails authentication
  bad <- ct
  bad[length(bad)] <- as.raw(bitwXor(as.integer(bad[length(bad)]), 0xff))
  expect_error(age_decrypt_raw(bad, identities = p$id), class = "age_error_decrypt")
})

test_that("all age errors share the age_error parent class", {
  expect_error(
    age_encrypt_raw(charToRaw("x"), recipients = "age1bad"),
    class = "age_error"
  )
})

test_that("file I/O guards raise age_error_io", {
  p <- new_pair()
  expect_error(
    age_encrypt_file("/no/such/input", recipients = p$rec),
    class = "age_error_io"
  )

  f <- withr::local_tempfile()
  writeBin(charToRaw("hi"), f)
  enc <- age_encrypt_file(f, recipients = p$rec)
  # will not overwrite an existing output
  expect_error(age_encrypt_file(f, recipients = p$rec), class = "age_error_io")
  expect_silent(age_encrypt_file(f, recipients = p$rec, overwrite = TRUE))

  # cannot infer plaintext path when input lacks a .age suffix
  notage <- withr::local_tempfile(fileext = ".bin")
  writeBin(enc |> readBin("raw", 1e6), notage)
  expect_error(
    age_decrypt_file(notage, identities = p$id),
    class = "age_error_io"
  )
})

test_that("text encryption rejects non-scalar input", {
  p <- new_pair()
  expect_error(
    age_encrypt_text(c("a", "b"), recipients = p$rec),
    class = "age_error_encrypt"
  )
  expect_error(
    age_encrypt_text(NA_character_, recipients = p$rec),
    class = "age_error_encrypt"
  )
})
