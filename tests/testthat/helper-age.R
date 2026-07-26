# Shared helpers for the test suite.

# A fresh identity and its recipient string.
new_pair <- function() {
  id <- age_keygen()
  list(id = id, rec = age_pubkey(id))
}

# Parse a CCTV-style vector fixture: `key: value` metadata lines, a blank
# line, then the raw ciphertext body.
read_vector <- function(path) {
  raw <- readBin(path, "raw", file.size(path))
  pair <- which(raw[-length(raw)] == as.raw(0x0a) & raw[-1L] == as.raw(0x0a))
  idx <- pair[1]
  meta_txt <- rawToChar(raw[seq_len(idx)])
  body <- if (idx + 2L <= length(raw)) raw[(idx + 2L):length(raw)] else raw[0]
  kv <- list()
  for (ln in strsplit(meta_txt, "\n", fixed = TRUE)[[1]]) {
    if (!grepl(": ", ln, fixed = TRUE)) next
    k <- sub(": .*", "", ln)
    kv[[k]] <- sub("^[^:]*: ", "", ln)
  }
  list(meta = kv, body = body)
}
