#ifndef AGE_AGECORE_H
#define AGE_AGECORE_H

/*
 * Encrypt/decrypt orchestration extracted from agec.c's CLI main() flow.
 * X25519 recipients only; scrypt (passphrase) input is rejected with an error
 * rather than prompting. Both return NULL on success or a human-readable error
 * string (owned by the library's shared error buffer; copy before reuse).
 *
 *   recs: nrec contiguous 32-byte X25519 public keys (recipients)
 *   ids:  nid  contiguous 32-byte X25519 private keys (identities)
 *
 * Must be included after "agec.h" (or at least common.h + io.h), which supply
 * the uchar/usize types and the Ibuf/Obuf definitions.
 */

struct Ibuf;
struct Obuf;

const char *age_encipher(struct Ibuf *in, struct Obuf *out,
		const uchar *recs, usize nrec);
const char *age_decipher(struct Ibuf *in, struct Obuf *out,
		const uchar *ids, usize nid);

/* Passphrase (scrypt) variants. `cost` is the log2 of the scrypt N factor. */
const char *age_encipher_passphrase(struct Ibuf *in, struct Obuf *out,
		const char *pass, uint cost);
const char *age_decipher_passphrase(struct Ibuf *in, struct Obuf *out,
		const char *pass);

#endif
