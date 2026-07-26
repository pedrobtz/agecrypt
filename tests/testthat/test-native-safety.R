# Regression tests for the native hardening fixes: the identity entry points
# must reject foreign or forged external pointers instead of crashing R, and
# header authentication must still reject tampering after switching the MAC
# comparison to constant time.

foreign_extptr <- function() {
  # the base DLL's info pointer is an external pointer with a tag that is not
  # ours; dereferencing it would be invalid, so it is a good hostile input
  p <- tryCatch(
    unclass(getLoadedDLLs()[["base"]])$info,
    error = function(e) NULL
  )
  if (!is.null(p) && typeof(p) == "externalptr") p else NULL
}

test_that("a non-external-pointer object with the identity class is rejected", {
  p <- new_pair()
  ct <- age_encrypt_raw(charToRaw("x"), recipients = p$rec)
  forged <- structure(1L, class = "age_identity")
  expect_error(
    age_decrypt_raw(ct, identities = forged),
    class = "age_error_identity"
  )
})

test_that("a foreign external pointer with the identity class is rejected", {
  fp <- foreign_extptr()
  skip_if(is.null(fp), "no foreign external pointer available")
  p <- new_pair()
  ct <- age_encrypt_raw(charToRaw("x"), recipients = p$rec)

  forged <- structure(fp, class = "age_identity")
  # tag mismatch -> clean error, not an invalid dereference/crash
  expect_error(
    age_decrypt_raw(ct, identities = forged),
    class = "age_error_identity"
  )
  expect_error(
    age_pubkey(forged),
    class = "age_error_identity"
  )
  # freeing a foreign pointer must be a safe no-op (never frees/clears it)
  expect_no_error(age_identity_free(forged))
})

test_that("freeing an identity twice does not crash", {
  id <- age_keygen()
  expect_no_error(age_identity_free(id))
  expect_no_error(age_identity_free(id)) # second free is a no-op
})

test_that("tampering with the header fails authentication", {
  p <- new_pair()
  ct <- age_encrypt_raw(charToRaw("authenticated payload"), recipients = p$rec)
  # flip a byte inside the header, well before the binary payload
  bad <- ct
  bad[30] <- as.raw(bitwXor(as.integer(bad[30]), 0xffL))
  expect_error(age_decrypt_raw(bad, identities = p$id), class = "age_error_decrypt")
})
