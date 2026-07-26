#!/usr/bin/env Rscript
# Build the fuzz seed corpus:
#   * the bodies of the vendored C2SP CCTV vectors (well-formed and malformed),
#   * a few authentic files encrypted to the harness's fixed identity /
#     passphrase, so seeds authenticate and reach the payload logic.
# Run from the package root:  Rscript fuzz/gen-corpus.R

suppressMessages(library(agecrypt))

here <- "fuzz"
dec_dir <- file.path(here, "corpus", "decrypt")
pw_dir <- file.path(here, "corpus", "passphrase")
dir.create(dec_dir, recursive = TRUE, showWarnings = FALSE)
dir.create(pw_dir, recursive = TRUE, showWarnings = FALSE)

# split a CCTV vector into (text metadata, raw body) at the first blank line
vector_parts <- function(path) {
  raw <- readBin(path, "raw", file.size(path))
  pair <- which(raw[-length(raw)] == as.raw(0x0a) & raw[-1L] == as.raw(0x0a))
  idx <- if (length(pair)) pair[1] else length(raw)
  body <- if (length(pair) && idx + 2L <= length(raw)) {
    raw[(idx + 2L):length(raw)]
  } else {
    raw[0]
  }
  list(meta = rawToChar(raw[seq_len(idx)]), body = body)
}
has_key <- function(meta, key) grepl(paste0("(^|\n)", key), meta)

vdirs <- c("dev/agec/test/vectors/dec", "dev/agec/test/vectors/dec-extra")
files <- unlist(lapply(vdirs, list.files, full.names = TRUE))
for (f in files) {
  v <- vector_parts(f)
  if (!length(v$body)) next
  if (has_key(v$meta, "passphrase:")) {
    writeBin(v$body, file.path(pw_dir, paste0("cctv_", basename(f))))
  } else if (has_key(v$meta, "identity:")) {
    writeBin(v$body, file.path(dec_dir, paste0("cctv_", basename(f))))
  }
}

# authentic seeds to the fixed identity used by fuzz_decrypt.c
secret <- "AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6"
rec <- age_pubkey(age_identity(secret))
for (n in c(0L, 1L, 200L, 70000L)) {
  msg <- as.raw(rep(65L, n))
  writeBin(age_encrypt_raw(msg, rec), file.path(dec_dir, sprintf("gen_bin_%d", n)))
  writeBin(age_encrypt_raw(msg, rec, armor = TRUE), file.path(dec_dir, sprintf("gen_arm_%d", n)))
}
# authentic passphrase seeds ("password", as the CCTV scrypt vectors use)
for (n in c(0L, 200L)) {
  msg <- as.raw(rep(66L, n))
  writeBin(age_encrypt_raw_passphrase(msg, passphrase = "password", log_n = 10),
    file.path(pw_dir, sprintf("gen_pw_%d", n)))
}

cat(sprintf("decrypt corpus:    %d files\n", length(list.files(dec_dir))))
cat(sprintf("passphrase corpus: %d files\n", length(list.files(pw_dir))))
