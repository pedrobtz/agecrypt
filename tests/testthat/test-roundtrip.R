test_that("raw round-trips for empty, tiny, and multi-chunk payloads", {
  p <- new_pair()
  for (msg in list("", "x", "hello world", strrep("A", 200000))) {
    ct <- age_encrypt_raw(charToRaw(msg), recipients = p$rec)
    expect_type(ct, "raw")
    pt <- age_decrypt_raw(ct, identities = p$id)
    expect_identical(rawToChar(pt), msg)
  }
})

test_that("armored output is PEM and returns raw, round-trips", {
  p <- new_pair()
  ct <- age_encrypt_raw(charToRaw("armored secret"), recipients = p$rec,
                        armor = TRUE)
  expect_type(ct, "raw")
  expect_match(rawToChar(ct), "^-----BEGIN AGE ENCRYPTED FILE-----")
  expect_identical(
    rawToChar(age_decrypt_raw(ct, identities = p$id)),
    "armored secret"
  )
})

test_that("age_decrypt_raw accepts an armored character scalar", {
  p <- new_pair()
  ct <- age_encrypt_text("via string", recipients = p$rec)
  # split into lines and drop the trailing newline, as readLines() would
  lines <- strsplit(sub("\n$", "", ct), "\n", fixed = TRUE)[[1]]
  expect_identical(
    rawToChar(age_decrypt_raw(lines, identities = p$id)),
    "via string"
  )
})

test_that("text round-trips and preserves UTF-8", {
  p <- new_pair()
  msg <- "café ☃ \U0001F510"
  ct <- age_encrypt_text(msg, recipients = p$rec)
  expect_type(ct, "character")
  out <- age_decrypt_text(ct, identities = p$id)
  expect_identical(out, msg)
  expect_identical(Encoding(out), "UTF-8")
})

test_that("age_decrypt_text rejects binary / non-UTF-8 payloads", {
  p <- new_pair()
  # embedded NUL
  ct1 <- age_encrypt_raw(as.raw(c(1, 0, 2)), recipients = p$rec)
  expect_error(age_decrypt_text(ct1, identities = p$id), class = "age_error_decrypt")
  # invalid UTF-8 byte sequence
  ct2 <- age_encrypt_raw(as.raw(c(0xff, 0xfe, 0x41)), recipients = p$rec)
  expect_error(age_decrypt_text(ct2, identities = p$id), class = "age_error_decrypt")
})

test_that("file round-trip with default suffixes", {
  p <- new_pair()
  f <- withr::local_tempfile()
  writeBin(charToRaw("file contents here"), f)
  enc <- age_encrypt_file(f, recipients = p$rec)
  expect_identical(enc, paste0(f, ".age"))
  dec <- age_decrypt_file(enc, output = withr::local_tempfile(),
                          identities = p$id)
  expect_identical(readBin(dec, "raw", 100), charToRaw("file contents here"))
})

test_that("multiple recipients can each decrypt", {
  a <- new_pair()
  b <- new_pair()
  ct <- age_encrypt_raw(charToRaw("shared"), recipients = c(a$rec, b$rec))
  expect_identical(rawToChar(age_decrypt_raw(ct, identities = a$id)), "shared")
  expect_identical(rawToChar(age_decrypt_raw(ct, identities = b$id)), "shared")
})

test_that("decrypt scans a multi-identity set for a match", {
  # Build a key file holding two identities; encrypt only to the second.
  kf1 <- withr::local_tempfile()
  kf2 <- withr::local_tempfile()
  age_keygen(kf1)
  age_keygen(kf2)
  combined <- withr::local_tempfile()
  writeLines(c(readLines(kf1), readLines(kf2)), combined)

  rec2 <- age_pubkey(age_identity(kf2))
  ct <- age_encrypt_raw(charToRaw("for the second key"), recipients = rec2)

  ids <- age_identity(combined) # holds both keys as one C-side array
  expect_identical(
    rawToChar(age_decrypt_raw(ct, identities = ids)),
    "for the second key"
  )
})
