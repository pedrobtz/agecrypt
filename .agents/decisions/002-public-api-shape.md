# ADR 002: Use explicit, type-stable, age-oriented R APIs

- **Status:** Accepted
- **Recorded:** 2026-07-26
- **Note:** This decision predates the ADR and consolidates the original merged
  design log.

## Context

The API must support raw secrets, large files, pasteable text, multiple keys,
and passphrase encryption while avoiding accidental secret disclosure and modal
argument combinations.

The original design considered recipient wrapper classes, S7 identities,
character armored results from raw functions, file wrappers over raw vectors,
runtime backend selectors, and implicit secret conversion.

## Decision

### Names and key objects

- Use age terminology: `recipient` for public keys and `identity` for private
  keys.
- Prefix exports with `age_`; do not define generic `encrypt()` or `decrypt()`.
- Represent recipients as plain validated `"age1..."` character strings.
- Represent one or more identities as an S3 object around one opaque native
  allocation.
- Export `age_identity()` for parsing inline identities and keyfiles.
- Do not provide `as.character()` or another implicit secret extractor.

### I/O shapes

- Make raw-vector encrypt/decrypt functions the composable in-memory primitives.
- Always return raw from raw functions, including armored ciphertext.
- Accept raw ciphertext or one armored character string for raw decryption.
- Provide text helpers that compose over raw operations and handle UTF-8.
- Give file functions a dedicated constant-memory native path.
- Defer R connection support until a callback-backed native adapter exists.

### Modes, errors, and safety

- Provide separate recipient and `_passphrase` functions; do not use a
  `passphrase=` mode switch.
- Bound scrypt `log_n` from 2 through 22.
- Use five specific condition classes under `age_error`: recipient, identity,
  encrypt, decrypt, and I/O.
- Require explicit overwrite permission and prevent accidental input/output
  collisions.
- Keep armor as an argument rather than a standalone API.
- Return ordinary raw or character values rather than an `age_ciphertext`
  wrapper.

### Backend and scope

- Expose one native backend with no CLI or `auto` selector.
- Ship X25519, scrypt, and armor support.
- Keep SSH recipients, plugins, hardware, and post-quantum recipients out of
  scope until the native backend supports their stanza types.

## Consequences

### Positive

- Function names communicate both operation and I/O shape.
- Return types do not change with `armor`.
- Secrets do not appear through routine printing or coercion.
- Large files do not round-trip through R memory.
- Callers can distinguish configuration, authentication, and storage failures.

### Negative

- The public surface has more explicit functions than a modal API.
- Recipient strings are revalidated during encryption rather than cached in an
  R wrapper.
- Exporting or migrating secret identities would require a deliberately named
  future API.
- Unsupported recipient types cannot be added only at the R layer.

## Related documents

- [Package design](../package-design.md)
- [Architecture](../architecture.md)
- [ADR 001](001-native-agec-backend.md)
