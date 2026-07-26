# ADR 001: Use one vendored native agec backend

- **Status:** Accepted
- **Recorded:** 2026-07-26
- **Note:** This decision predates the ADR and is recorded from the implemented
  package design.

## Context

The package needs to read and write the age v1 format without requiring users to
install an external executable or cryptographic library.

agec is a small 0BSD C implementation that includes ChaCha20-Poly1305,
Curve25519, HKDF, HMAC, scrypt, SHA-256, ASCII armor, and age v1 parsing. Its
main limitation is structural: it is a CLI whose orchestration and I/O are built
around file descriptors.

Alternatives considered included:

- wrapping the reference `age` CLI;
- supporting native, CLI, and automatic backend selection;
- using file-only operations and omitting raw vectors;
- adding a separate cryptographic library dependency.

## Decision

`agecrypt` has exactly one runtime backend: a vendored agec snapshot compiled
into the R package.

- Extract the CLI orchestration into callable native functions.
- Replace OpenSSL randomness with operating-system CSPRNGs.
- Add memory-backed virtual descriptors for raw-vector operations.
- Retain real-descriptor streaming for file operations.
- Use the reference `age` or `rage` CLI only as a test oracle.
- Stage upstreamable fixes and immutable vendor snapshots in
  `pedrobtz/agec`; keep package-only R integration in `agecrypt`.

The initial feature scope is what agec implements: X25519 recipients, scrypt
passphrases, and ASCII armor.

## Consequences

### Positive

- Users need no OpenSSL, Go, Rust, or external age installation.
- Raw decryption can keep plaintext off disk.
- File operations remain constant-memory.
- Runtime behavior cannot vary because of backend discovery or version skew.
- The 0BSD vendored code has straightforward redistribution terms.

### Negative

- The package owns native integration, platform randomness, and vendoring work.
- The backend is not reentrant because inherited and package I/O state is global.
- R connections require another native I/O adapter.
- SSH, plugins, hardware, and post-quantum recipients require backend protocol
  work rather than R wrappers.

## Related documents

- [Architecture](../architecture.md)
- [Vendoring agec](../vendoring-agec.md)
- [`inst/COPYRIGHTS`](../../inst/COPYRIGHTS)
