# Regression tests for the file-output safety fixes: owner-only key files,
# same-file rejection, atomic writes that preserve a pre-existing destination
# on failure, and no leftover temp files.

temp_siblings <- function(path) {
  list.files(dirname(path),
    pattern = "\\.age-[0-9a-f]{16}$", full.names = TRUE
  )
}

test_that("generated key files are not world/group readable", {
  skip_on_os("windows") # POSIX permission bits only
  kf <- withr::local_tempfile()
  old <- Sys.umask("0000") # force a permissive umask
  withr::defer(Sys.umask(old))
  age_keygen(kf)
  expect_identical(as.character(file.mode(kf)), "600")
})

test_that("file APIs reject output identical to input", {
  p <- new_pair()
  f <- withr::local_tempfile(fileext = ".txt")
  writeBin(charToRaw("IMPORTANT PLAINTEXT"), f)

  expect_error(
    age_encrypt_file(f, output = f, recipients = p$rec, overwrite = TRUE),
    class = "age_error_io"
  )
  # a relative alias of the same file is also rejected
  withr::with_dir(dirname(f), {
    base <- basename(f)
    expect_error(
      age_encrypt_file(base, output = file.path(".", base),
        recipients = p$rec, overwrite = TRUE),
      class = "age_error_io"
    )
  })
  # the input is untouched
  expect_identical(readBin(f, "raw", 100), charToRaw("IMPORTANT PLAINTEXT"))
})

test_that("a symlink pointing at the input is rejected as the same file", {
  skip_on_os("windows")
  p <- new_pair()
  f <- withr::local_tempfile(fileext = ".txt")
  writeBin(charToRaw("PLAINTEXT"), f)
  link <- withr::local_tempfile(fileext = ".txt")
  ok <- file.symlink(f, link)
  skip_if_not(ok, "could not create a symlink")
  expect_error(
    age_encrypt_file(f, output = link, recipients = p$rec, overwrite = TRUE),
    class = "age_error_io"
  )
  expect_identical(readBin(f, "raw", 100), charToRaw("PLAINTEXT"))
})

test_that("a failed decryption preserves a pre-existing destination", {
  p <- new_pair()
  out <- withr::local_tempfile(fileext = ".age")
  writeBin(charToRaw("PRE-EXISTING DESTINATION"), out)

  bad <- withr::local_tempfile()
  writeBin(as.raw(1:8), bad) # not valid age ciphertext

  expect_error(
    age_decrypt_file(bad, output = out, identities = p$id, overwrite = TRUE),
    class = "age_error_decrypt"
  )
  expect_true(file.exists(out))
  expect_identical(readBin(out, "raw", 100), charToRaw("PRE-EXISTING DESTINATION"))
  expect_length(temp_siblings(out), 0L) # no leftover temp file
})

test_that("a failed encryption preserves a pre-existing destination", {
  # encrypt with an unusable recipient after a valid output already exists
  out <- withr::local_tempfile(fileext = ".age")
  writeBin(charToRaw("KEEP ME"), out)
  f <- withr::local_tempfile(fileext = ".txt")
  writeBin(charToRaw("plaintext"), f)

  # a malformed recipient fails before any output is produced
  expect_error(
    age_encrypt_file(f, output = out, recipients = "age1nope", overwrite = TRUE),
    class = "age_error_recipient"
  )
  expect_identical(readBin(out, "raw", 100), charToRaw("KEEP ME"))
})

test_that("successful overwrite replaces the destination and leaves no temp", {
  p <- new_pair()
  f <- withr::local_tempfile(fileext = ".txt")
  writeBin(charToRaw("v2 contents"), f)
  out <- withr::local_tempfile(fileext = ".age")
  writeBin(charToRaw("stale ciphertext"), out)

  age_encrypt_file(f, output = out, recipients = p$rec, overwrite = TRUE)
  dec <- age_decrypt_file(out, output = withr::local_tempfile(), identities = p$id)
  expect_identical(readBin(dec, "raw", 100), charToRaw("v2 contents"))
  expect_length(temp_siblings(out), 0L)
})

test_that("native write refuses to clobber for overwrite = FALSE (no TOCTOU race)", {
  # Bypass the R-side guard_output() by calling the native entry point directly
  # with overwrite = FALSE, simulating a destination that appears between the
  # R existence check and the C write. The C layer must be authoritative.
  p <- new_pair()
  f <- withr::local_tempfile(fileext = ".txt")
  writeBin(charToRaw("plaintext"), f)
  out <- withr::local_tempfile(fileext = ".age")
  writeBin(charToRaw("PRE-EXISTING DESTINATION"), out)

  status <- .Call(
    agecrypt:::C_age_c_encrypt_path,
    normalizePath(f), normalizePath(out), p$rec, FALSE, FALSE
  )
  expect_false(identical(status[[1L]], "")) # errored, did not clobber
  expect_match(status[[2L]], "exists")
  expect_identical(
    readBin(out, "raw", 100), charToRaw("PRE-EXISTING DESTINATION")
  )
  expect_length(temp_siblings(out), 0L)

  # overwrite = TRUE replaces atomically
  status2 <- .Call(
    agecrypt:::C_age_c_encrypt_path,
    normalizePath(f), normalizePath(out), p$rec, FALSE, TRUE
  )
  expect_identical(status2[[1L]], "")
  expect_identical(
    rawToChar(age_decrypt_raw(readBin(out, "raw", 1e5), p$id)), "plaintext"
  )
})

test_that("encrypting a file over itself is safe once distinctness is bypassed", {
  # Even if a caller reaches C with input == output (e.g. an undetected alias),
  # the atomic write must not destroy data. Exercise the native path directly.
  p <- new_pair()
  f <- withr::local_tempfile(fileext = ".bin")
  writeBin(charToRaw("ATOMIC SELF ENCRYPT"), f)

  status <- .Call(
    agecrypt:::C_age_c_encrypt_path,
    normalizePath(f), normalizePath(f), p$rec, FALSE, TRUE
  )
  expect_identical(status[[1L]], "") # success
  # f now holds its own ciphertext, which decrypts back to the original
  back <- age_decrypt_raw(readBin(f, "raw", 1e5), identities = p$id)
  expect_identical(rawToChar(back), "ATOMIC SELF ENCRYPT")
})
