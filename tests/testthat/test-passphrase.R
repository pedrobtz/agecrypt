test_log_n <- 8L

test_that("raw passphrase round-trips for empty, tiny, and multi-chunk data", {
  for (msg in list("", "x", "top secret", strrep("Z", 200000))) {
    ct <- age_encrypt_raw_passphrase(
      charToRaw(msg),
      passphrase = "hunter2",
      log_n = test_log_n
    )
    expect_type(ct, "raw")
    pt <- age_decrypt_raw_passphrase(ct, passphrase = "hunter2")
    expect_identical(rawToChar(pt), msg)
  }
})

test_that("default passphrase work factor round-trips once", {
  ct <- age_encrypt_raw_passphrase(charToRaw("default"), passphrase = "hunter2")
  expect_identical(
    rawToChar(age_decrypt_raw_passphrase(ct, passphrase = "hunter2")),
    "default"
  )
})

test_that("armored passphrase output is PEM and round-trips", {
  ct <- age_encrypt_raw_passphrase(
    charToRaw("armored pw"),
    passphrase = "pw",
    armor = TRUE,
    log_n = test_log_n
  )
  expect_match(rawToChar(ct), "^-----BEGIN AGE ENCRYPTED FILE-----")
  expect_identical(
    rawToChar(age_decrypt_raw_passphrase(ct, passphrase = "pw")),
    "armored pw"
  )
})

test_that("file passphrase round-trip with default suffixes", {
  f <- withr::local_tempfile(fileext = ".txt")
  writeBin(charToRaw("file pw data"), f)
  enc <- age_encrypt_file_passphrase(f, passphrase = "fp", log_n = test_log_n)
  expect_identical(enc, paste0(f, ".age"))
  dec <- age_decrypt_file_passphrase(
    enc,
    output = withr::local_tempfile(),
    passphrase = "fp"
  )
  expect_identical(readBin(dec, "raw", 100), charToRaw("file pw data"))
})

test_that("wrong passphrase fails to decrypt", {
  ct <- age_encrypt_raw_passphrase(
    charToRaw("secret"),
    passphrase = "right",
    log_n = test_log_n
  )
  expect_error(
    age_decrypt_raw_passphrase(ct, passphrase = "wrong"),
    class = "age_error_decrypt"
  )
})

test_that("passphrase and recipient modes do not cross-decrypt", {
  id <- age_keygen()
  pw_ct <- age_encrypt_raw_passphrase(
    charToRaw("x"),
    passphrase = "p",
    log_n = test_log_n
  )
  x_ct <- age_encrypt_raw(charToRaw("x"), recipients = age_pubkey(id))
  # a passphrase file is not decryptable with an identity ...
  expect_error(
    age_decrypt_raw(pw_ct, identities = id),
    class = "age_error_decrypt"
  )
  # ... and an X25519 file is not decryptable with a passphrase
  expect_error(
    age_decrypt_raw_passphrase(x_ct, passphrase = "p"),
    class = "age_error_decrypt"
  )
})

test_that("a higher work factor still round-trips", {
  ct <- age_encrypt_raw_passphrase(
    charToRaw("wf"),
    passphrase = "p",
    log_n = 12
  )
  expect_identical(
    rawToChar(age_decrypt_raw_passphrase(ct, passphrase = "p")),
    "wf"
  )
})

test_that("passphrase and log_n arguments are validated", {
  expect_error(
    age_encrypt_raw_passphrase(charToRaw("x"), passphrase = c("a", "b")),
    class = "age_error_encrypt"
  )
  expect_error(
    age_encrypt_raw_passphrase(charToRaw("x"), passphrase = ""),
    class = "age_error_encrypt"
  )
  expect_error(
    age_encrypt_raw_passphrase(charToRaw("x"), passphrase = "p", log_n = 99),
    class = "age_error_encrypt"
  )
  expect_error(
    age_encrypt_raw_passphrase(charToRaw("x"), passphrase = "p", log_n = 1.5),
    class = "age_error_encrypt"
  )
  # NULL passphrase in a non-interactive session is an error, not a hang
  expect_error(
    age_encrypt_raw_passphrase(charToRaw("x"), passphrase = NULL),
    class = "age_error_encrypt"
  )
})

test_that("age_encrypt_raw_passphrase requires raw input", {
  expect_error(
    age_encrypt_raw_passphrase("not raw", passphrase = "p"),
    class = "age_error_encrypt"
  )
})
