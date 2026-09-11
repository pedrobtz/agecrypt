# Working on: binding soundness review

Review of the R↔C boundary (`src/binding.c`, `src/init.c`, `src/memio.c`,
`src/fileio.c`, `src/platform.c`) and the vendored `agec` code those entry
points drive. Findings below are ordered by severity.

Status key: **[fixed]** applied in the working tree · **[open]** reported only,
no code changed.

---

## 1. [fixed] Silent data loss at the 8 KiB output-buffer boundary

**Where:** `src/agec/io.c`, `bwrite()`

`bwrite()` flushed `b->cur` bytes when it should flush `b->cur + c`. The
`memcpy` immediately above fills `buf[cur .. IOBUFSIZE)` with the first `c`
bytes of the incoming write; writing only `b->cur` drops them, and the
following `memcpy` overwrites that region at offset 0.

```c
rest = IOBUFSIZE - b->cur;
c = (rest > nbytes) ? nbytes : rest;
memcpy(b->buf.buf + b->cur, buf, c);   /* fills buf[cur .. IOBUFSIZE) */
if (rest > nbytes) {
        b->cur += nbytes;
        return 0;
} else {
        ret = writeall(b->fd, b->buf.buf, b->cur);   /* BUG: drops the c bytes */
        ...
        memcpy(b->buf.buf, (uchar *)buf + rest, nbytes - rest);
        b->cur = nbytes - rest;
}
```

Reachable from the public API, and silent in **both** directions:

| Path | Trigger | Symptom |
|---|---|---|
| Encrypt | plaintext 7992–8192 bytes (186 sizes) | `age_encrypt_raw()` returns success with a truncated ciphertext. 8000 bytes in produced a 192-byte ciphertext that no longer decrypts. Permanent data loss. |
| Decrypt | final STREAM chunk decrypting to exactly 8192 bytes (e.g. 73728-byte plaintext) | `age_decrypt_raw()` returns success with short plaintext and **no error at all**. 73728 bytes came back as 65536. |

Armored output is affected too, via the decrypt side's unarmored `Obuf`.

### Why it was not caught

- `test-roundtrip.R` covered 0, 1, 11 and 200000 bytes.
- The interop fixture sweep (`tools/gen-interop-fixtures.R`) uses
  `0, 5, 34, 35, 100, 70000` — chosen to straddle the 35-byte armor probe and
  the 64 KiB STREAM chunk, but not the 8 KiB `Obuf` boundary.
- The fuzz harness targets decrypt only, so it cannot reach the encrypt-side
  case, and random mutation will not produce a valid ciphertext whose final
  chunk decrypts to exactly 8192 bytes.

### Fix applied

One line in `bwrite()`, plus a site comment in the house style used for the
other divergences:

```c
ret = writeall(b->fd, b->buf.buf, b->cur + c);
```

### Verification

- 178 tests pass (was 162).
- `R CMD check`: 0 errors, 0 warnings, 0 notes.
- Standalone ASAN+UBSAN harness: 2490 encrypt→decrypt roundtrips across all
  four buffer boundaries (8 KiB `Obuf`, 12 KiB armor `abuf`, 64 KiB STREAM
  chunk, 35-byte armor probe), binary and armored — 0 failures, no memory
  errors. The same harness reports 190 failures against the unfixed code.
- New regression tests confirmed sensitive: 3 failures with the bug
  reintroduced, 0 with the fix.

### Follow-up still owed

Per `.agents/vendoring-agec.md`, this belongs upstream in `pedrobtz/agec`, not
in this tree:

- [ ] Push the `bwrite()` fix to a `fix/*` branch on the agec fork.
- [ ] Re-vendor under a new immutable tag via
      `tools/update-vendored-agec.sh <ref> <full-sha>`.
- [ ] Move the `inst/COPYRIGHTS` entry from `[pending upstream]` to
      `[in snapshot]` and update the tag named in that section's preamble.
- [ ] Consider widening `tools/gen-interop-fixtures.R` sizes to include
      8000 and 73728, so the boundary is locked in against reference `age`
      rather than only self-consistently.

### Files changed

| File | Change |
|---|---|
| `src/agec/io.c` | The fix + divergence comment. |
| `inst/COPYRIGHTS` | Recorded as `[pending upstream]`; intro now says "three groups". |
| `tests/testthat/test-roundtrip.R` | Two boundary regression tests (binary + armored). |
| `.Rbuildignore` | Excludes this file from the build. |

---

## 2. [open] Stale error messages from the shared `ebuf`

**Where:** `src/platform.c`, `eget()`

```c
const char *
eget(void)
{
        if(*ebuf)
                return ebuf;
        return strerror(errno);
}
```

`ebuf` is a process-global in the vendored `util.c` that is never cleared.
Once any operation populates it (via `eset()` or `ewrap()`), every later
`eget()`/`esys()` caller that did *not* set it reports the **previous**
operation's message instead of the real `strerror(errno)`.

Reachable path: a failed decrypt populates `ebuf` through `ewrap()`; a later
file encrypt that hits `ENOSPC` in `bflush()` returns
`"error parsing header: ..."` instead of `"No space left on device"`.

Severity: message quality only — no incorrect success, no memory unsafety.
Found by reading; **not reproduced** (would need a full filesystem).

Suggested fix: clear `ebuf` at the start of each native entry point, or have
`eget()` consume it (copy out, then zero).

---

## 3. [open] memfd slot leak if R longjmps out mid-call

**Where:** `src/binding.c`, the four raw entry points

Each raw entry point allocates its result *after* the operation succeeds:

```c
odata = memdata(vout, &olen);
res = PROTECT(Rf_allocVector(RAWSXP, olen));   /* can longjmp on OOM */
...
memclose(vin);
memclose(vout);
```

If `Rf_allocVector` fails, R longjmps and the two `memclose()` calls never
run. `MEMFD_MAX` is 8 and each operation holds 2 slots, so four such failures
exhaust the table and **every subsequent operation fails permanently** with
`"failed to allocate buffer"` for the lifetime of the session.

Suggested fix: `R_UnwindProtect` around the operation, or reserve the result
vector before opening the streams.

---

## 4. [open] `recs` leaks if `RAW(data)` longjmps

**Where:** `src/binding.c`, `age_c_encrypt()` and `age_c_encrypt_path()`

`parse_recipients()` mallocs `recs` before `RAW(data)` is evaluated. A
non-raw `data` makes `RAW()` raise an R error, longjmping past the `free()`.

Only reachable by calling the internal symbol directly
(`agecrypt:::C_age_c_encrypt`), since the R layer checks `is.raw(x)` first —
defense-in-depth, bounded leak. Confirmed no crash: 12 hostile inputs probed
through the internal symbols all produced clean R errors.

---

## 5. [open] Secret not scrubbed on one error path

**Where:** `src/binding.c`, `age_c_identity_parse()`

```c
for(i = 0; i < n; i++) {
        const char *s = CHAR(STRING_ELT(secrets, i));
        if(strlen(s) != PRIVKEYLEN) {
                id_destroy(id);
                return result_err("identity", "invalid identity string");
        }                                  /* ^ bech not wiped here */
        memcpy(bech, s, PRIVKEYLEN);
        ...
}
wipe(bech, sizeof(bech));
```

On the length-mismatch path `bech` still holds the **previous** element's
secret key. Every other exit from this function wipes it. Triggered by
`age_identity(c(<valid key>, "short"))`.

Suggested fix: `wipe(bech, sizeof(bech));` before that `return`.

---

## 6. [open] Secrets pass through R's immortal string cache

**Where:** `R/identity.R`, `collect_secret_strings()` / `read_keyfile_secrets()`

Loading identities from a key file builds an R character vector of
`AGE-SECRET-KEY-1…` strings and passes it to `age_c_identity_parse()`. R
interns every string in the global CHARSXP cache, which is effectively never
released — so the secret stays in R's heap in plaintext for the lifetime of
the process, visible to a core dump or memory scrape.

This is in tension with the stated invariant *"keep identity secrets in
opaque, scrubbed native allocations; do not print, coerce, or expose secret
bytes."* `age_keygen()` honours it (generated in C, never returned to R);
`age_identity(<file>)` does not.

Options, in increasing order of effort:

1. Document the limitation in `?age_identity` and `.agents/package-design.md`.
2. Read key files in C (pass the *path* to the native layer, not the parsed
   secrets), so file-loaded identities never enter R memory. Inline
   `AGE-SECRET-KEY-1…` strings would remain a caller's choice.

---

## 7. [open] `1 << factor` UB for out-of-range `log_n`

**Where:** `src/agec/scrypt.c`, `wrapkey()`

`1 << factor` with `factor >= 32` is undefined behavior (`1` is `int`), and
`factor == 31` overflows signed int. `age_c_encrypt_passphrase()` casts
`Rf_asInteger(logn)` straight to `uint` with no native bound.

Not reachable from the public API — `check_log_n()` enforces 2..22. Direct
calls to the internal symbol with `NA_integer_` produce
`(uint)INT_MIN == 2147483648`, which on x86 silently shifts by `count % 32`
and writes a header claiming a nonsensical cost, yielding an undecryptable
file rather than a crash.

**The decrypt side is correctly bounded** and needs no change: `scryptcost()`
accepts digits only, rejects leading zeros, and caps at 4 digits
(cost ∈ [1, 9999]); `agecore.c` then rejects `cost > SCRYPTMAXCOST` (22)
before `scryptgetkey()` runs. No attacker-controlled UB from a file header.

Suggested fix: validate `cost` in C as well as in R.

---

## 8. [open] Dead code in `incnonce()`

**Where:** `src/agec/payload.c`

```c
for(i = 10; i > 0; i--) {
        nonce[i]++;
        if(nonce[i] != 0)
                break;
        if(i == 0)      /* unreachable: loop stops at i == 1 */
                return "payload is too long; chunk counter wrapped";
}
```

Two issues: the wrap check can never fire, so overflow returns success
silently; and `nonce[0]` is never incremented, making the counter 10 bytes
rather than the age spec's 11. Unreachable in practice (~2^96 bytes of
payload), so cosmetic — but the guard does not do what it says.

---

## Verified sound (no action needed)

Checked and found correct, recorded so the next review need not redo it:

- **`(status, payload)` protocol.** No `Rf_error()` mid-operation anywhere;
  every error path copies the message out of `ebuf`, closes its memfds, frees
  its allocations, and returns an error suffix. `PROTECT`/`UNPROTECT` balanced
  in all entry points; no R allocation between an unprotected `SEXP` and its
  use.
- **External pointer safety.** `id_addr()` checks `TYPEOF` *and* the tag, so
  forged (`structure(1L, class = "age_identity")`) and foreign (base DLL info
  pointer) inputs are rejected rather than dereferenced. Double free is a
  no-op. Probed 12 hostile inputs through the internal symbols — clean R
  errors, no crash.
- **Atomic output.** Temp file + `fsync` + `link()`/`unlink()` no-clobber
  closes the check-then-write race that a bare `rename()` would leave open,
  with an `access()`+`rename()` fallback for filesystems without hard links.
  Destination is never truncated up front and survives any failure untouched.
- **bech32 buffer sizes.** Contract is `strlen(label) + datalen + 8`; needs 43
  (public) and 55 (secret) against buffers of 63 and 75. Encoded lengths 62
  and 74 match `PUBKEYLEN`/`PRIVKEYLEN`, and `x25519privkey()`'s unchecked
  `bech[74] = '\0'` is safe because the caller verifies `strlen` first.
- **Partially initialized `Obuf`.** `binding.c` sets only `fd`/`cur`/`isarmor`,
  leaving the 8 KiB union uninitialized — safe, because `cur = 0` means every
  byte is written before it is read, and `wipe(&ob, sizeof(ob))` scrubs the
  whole struct afterwards.
- **Randomness.** OS CSPRNG only on every platform (`BCryptGenRandom`,
  `arc4random_buf`, `getentropy` with the 256-byte cap looped). No `exit()`,
  `abort()`, or writes to standard streams in compiled code.
- **Armor write path.** `awrite()` loops and flushes correctly — no analogue
  of finding 1. Confirmed by a 333-size armored sweep around 8 KiB, 12 KiB
  (`IOABUFRAWSIZE`), 24 KiB and 64 KiB.
- **Constant-time MAC compare.** `ct_eq()` accumulates with `|=` over the full
  32 bytes; header tampering still rejected.
- **Build config.** `src/Makevars` and `src/Makevars.win` object lists are
  identical; `-iquote` preserved in both so agec's `io.h` does not shadow the
  Windows system header.

---

## Reproduction

Harnesses live in the session scratchpad, not the repo. To rebuild the
sanitizer harness:

```sh
clang -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 \
  -iquote src/agec -iquote src/agec/crypto -iquote src \
  rt.c src/memio.c src/platform.c src/agec/*.c src/agec/crypto/*.c -o rt
ASAN_OPTIONS=detect_leaks=0 ./rt
```

where `rt.c` drives `age_encipher`/`age_decipher` over `memopen_read`/
`memopen_write` across the boundary sizes. The committed regression tests in
`tests/testthat/test-roundtrip.R` cover the same ground from R.

## Notes

- `air` is not on `PATH` in this environment, so new test code is hand-matched
  to surrounding style rather than formatter-verified. Worth running
  `air format .` before committing.
