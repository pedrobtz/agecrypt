# Known-answer tests against a curated subset of the C2SP CCTV age test
# vectors (X25519 and scrypt/passphrase) that ship with the vendored agec
# sources. Each vector carries the expected outcome and, for success cases,
# the SHA-256 of the plaintext.

vector_dir <- test_path("fixtures", "vectors")

# decrypt a parsed vector in whichever mode its metadata implies
decrypt_vector <- function(v) {
  if (!is.null(v$meta$passphrase)) {
    age_decrypt_raw_passphrase(v$body, passphrase = v$meta$passphrase)
  } else {
    age_decrypt_raw(v$body, identities = v$meta$identity)
  }
}

test_that("CCTV success vectors decrypt to the expected payload", {
  skip_if_not_installed("openssl")
  for (name in c("armor", "armor_full_last_line", "scrypt")) {
    v <- read_vector(file.path(vector_dir, name))
    expect_identical(v$meta$expect, "success", info = name)
    got <- paste0(openssl::sha256(decrypt_vector(v)))
    expect_identical(got, v$meta$payload, info = name)
  }
})

test_that("CCTV malformed vectors are rejected with age_error_decrypt", {
  success <- c("armor", "armor_full_last_line", "scrypt")
  for (name in setdiff(list.files(vector_dir), success)) {
    v <- read_vector(file.path(vector_dir, name))
    expect_false(identical(v$meta$expect, "success"), info = name)
    expect_error(decrypt_vector(v), class = "age_error_decrypt", info = name)
  }
})
