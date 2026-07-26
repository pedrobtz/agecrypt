/*
 * R <-> agec entry points (.Call).
 *
 * Concurrency/reentrancy contract: these functions are NOT reentrant and must
 * be called synchronously from R's single main thread -- which is exactly how
 * R evaluates .Call(). Two agec operations must never run concurrently or
 * nested, because the backend keeps mutable process-global state:
 *   - the error message buffer `ebuf` in src/agec/util.c (agec functions return
 *     const char* pointers into it), and
 *   - the in-memory stream table `memtab` in src/memio.c.
 * Each operation runs to completion before the next, and an error string is
 * consumed immediately after the call that produced it, so this global state
 * is effectively operation-local under R. Do not call this code from multiple
 * threads or re-enter it from a callback without first making that state
 * operation-local.
 */

#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>

#include <errno.h>
#include <string.h>

#include "agec.h"
#include "agecore.h"
#include "memio.h"
#include "fileio.h"

/* O_BINARY suppresses CRLF/Ctrl-Z translation when reading ciphertext on
   Windows; it does not exist on POSIX, where file I/O is already binary. */
#ifndef O_BINARY
#define O_BINARY 0
#endif

#define PUBKEYLEN  62   /* "age1..." recipient string length          */
#define PRIVKEYLEN 74   /* "AGE-SECRET-KEY-1..." identity string length */

/*
 * Every entry point returns a length-2 list: element 0 is a status string
 * (empty on success, otherwise an error-class suffix such as "decrypt" that
 * the R layer maps to an age_error_<suffix> condition) and element 1 is the
 * payload (result on success, message on failure). This keeps all condition
 * signalling in R and avoids longjmp'ing out of C with buffers still open.
 */

static SEXP
result_ok(SEXP payload)
{
	SEXP out;

	PROTECT(payload);
	out = PROTECT(Rf_allocVector(VECSXP, 2));
	SET_VECTOR_ELT(out, 0, Rf_mkString(""));
	SET_VECTOR_ELT(out, 1, payload);
	UNPROTECT(2);
	return out;
}

static SEXP
result_err(const char *cls, const char *msg)
{
	SEXP out;

	out = PROTECT(Rf_allocVector(VECSXP, 2));
	SET_VECTOR_ELT(out, 0, Rf_mkString(cls));
	SET_VECTOR_ELT(out, 1, Rf_mkString(msg));
	UNPROTECT(1);
	return out;
}

/* ---- identity external pointer ---- */

typedef struct AgeIdentities AgeIdentities;
struct AgeIdentities {
	uchar    *keys;   /* n contiguous 32-byte X25519 private keys */
	R_xlen_t  n;
};

static SEXP
id_tag(void)
{
	return Rf_install("age_identity_ptr");
}

static AgeIdentities *
id_addr(SEXP ext)
{
	/*
	 * Check the tag as well as the type: a foreign external pointer (or a
	 * forged object carrying the age_identity class) must never be cast to
	 * AgeIdentities *, which would be an invalid read/free and crash R.
	 */
	if(TYPEOF(ext) != EXTPTRSXP || R_ExternalPtrTag(ext) != id_tag())
		return NULL;
	return (AgeIdentities *)R_ExternalPtrAddr(ext);
}

static void
id_destroy(AgeIdentities *id)
{
	if(id == NULL)
		return;
	if(id->keys != NULL) {
		wipe(id->keys, (usize)id->n * 32);
		free(id->keys);
	}
	free(id);
}

static void
id_finalizer(SEXP ext)
{
	AgeIdentities *id = id_addr(ext);   /* NULL if foreign or already freed */

	if(id == NULL)
		return;
	id_destroy(id);
	R_ClearExternalPtr(ext);
}

static SEXP
id_wrap(AgeIdentities *id)
{
	SEXP ext;

	ext = PROTECT(R_MakeExternalPtr(id, id_tag(), R_NilValue));
	R_RegisterCFinalizerEx(ext, id_finalizer, TRUE);
	UNPROTECT(1);
	return ext;
}

/* ---- recipient parsing (shared by encrypt entry points) ---- */

/*
 * On success stores a freshly malloc'd nrec*32 pubkey array in *out and
 * returns NULL. On failure returns an error message and leaves *out NULL.
 */
static const char *
parse_recipients(SEXP recipients, uchar **out, R_xlen_t *nout)
{
	R_xlen_t nrec, i;
	uchar *recs;
	char bech[PUBKEYLEN + 1];

	*out = NULL;
	nrec = XLENGTH(recipients);
	if(nrec == 0)
		return "no recipients supplied";
	recs = malloc((usize)nrec * 32);
	if(recs == NULL)
		return "out of memory";
	for(i = 0; i < nrec; i++) {
		const char *s = CHAR(STRING_ELT(recipients, i));
		if(strlen(s) != PUBKEYLEN) {
			free(recs);
			return "invalid recipient string";
		}
		memcpy(bech, s, PUBKEYLEN);
		bech[PUBKEYLEN] = '\0';             /* mutable copy: bech32 rewrites it */
		if(!x25519pubkey(bech, recs + i * 32)) {
			free(recs);
			return "failed to parse recipient key";
		}
	}
	*out = recs;
	*nout = nrec;
	return NULL;
}

/* ---- keygen ---- */

SEXP
age_c_keygen(void)
{
	uchar priv[32], pub[32];
	AgeIdentities *id;

	if(!randombuf(priv, 32))
		return result_err("internal", "failed to generate private key");
	if(!x25519pub(pub, priv)) {
		wipe(priv, sizeof(priv));
		return result_err("internal", "curve25519 low order point");
	}
	wipe(pub, sizeof(pub));
	id = malloc(sizeof(*id));
	if(id == NULL) {
		wipe(priv, sizeof(priv));
		return result_err("internal", "out of memory");
	}
	id->keys = malloc(32);
	if(id->keys == NULL) {
		free(id);
		wipe(priv, sizeof(priv));
		return result_err("internal", "out of memory");
	}
	memcpy(id->keys, priv, 32);
	id->n = 1;
	wipe(priv, sizeof(priv));
	return result_ok(id_wrap(id));
}

/* ---- identity parse ---- */

SEXP
age_c_identity_parse(SEXP secrets)
{
	R_xlen_t n, i;
	AgeIdentities *id;
	char bech[PRIVKEYLEN + 1];

	n = XLENGTH(secrets);
	if(n == 0)
		return result_err("identity", "no identities supplied");
	id = malloc(sizeof(*id));
	if(id == NULL)
		return result_err("identity", "out of memory");
	id->keys = malloc((usize)n * 32);
	if(id->keys == NULL) {
		free(id);
		return result_err("identity", "out of memory");
	}
	id->n = n;
	for(i = 0; i < n; i++) {
		const char *s = CHAR(STRING_ELT(secrets, i));
		if(strlen(s) != PRIVKEYLEN) {
			id_destroy(id);
			return result_err("identity", "invalid identity string");
		}
		memcpy(bech, s, PRIVKEYLEN);
		bech[PRIVKEYLEN] = '\0';
		if(!x25519privkey(bech, id->keys + i * 32)) {
			wipe(bech, sizeof(bech));
			id_destroy(id);
			return result_err("identity", "failed to parse identity");
		}
	}
	wipe(bech, sizeof(bech));
	return result_ok(id_wrap(id));
}

/* ---- derive public recipient strings ---- */

SEXP
age_c_identity_pubkeys(SEXP ext)
{
	AgeIdentities *id;
	SEXP out;
	R_xlen_t i;
	uchar pub[32];
	char label[] = "age";
	char bech[PUBKEYLEN + 1];

	id = id_addr(ext);
	if(id == NULL || id->keys == NULL)
		return result_err("identity", "invalid or freed identity");
	out = PROTECT(Rf_allocVector(STRSXP, id->n));
	for(i = 0; i < id->n; i++) {
		if(!x25519pub(pub, id->keys + i * 32)) {
			UNPROTECT(1);
			return result_err("identity", "curve25519 low order point");
		}
		if(!bech32encode(label, pub, 32, (uchar *)bech)) {
			UNPROTECT(1);
			return result_err("identity", "failed to encode public key");
		}
		SET_STRING_ELT(out, i, Rf_mkCharLen(bech, PUBKEYLEN));
	}
	wipe(pub, sizeof(pub));
	UNPROTECT(1);
	return result_ok(out);
}

/* ---- atomic output helpers ---- */

/*
 * Finalise a temp file written for `outp`: flush it to stable storage, close
 * it, and move it onto the destination. With `overwrite` zero the move is a
 * no-clobber operation, so a destination that appears between the R-side
 * existence check and here is not silently replaced. Only after this returns 0
 * does the destination reflect the new contents; on any failure the temp file
 * is removed, the destination is left untouched, and a message is copied into
 * errbuf.
 */
static int
commit_output(int tmpfd, const char *tmppath, const char *outp, int overwrite,
		char *errbuf, usize errcap)
{
	int saved;

	if(age_fsync(tmpfd) != 0) {
		saved = errno;
		close(tmpfd);
		unlink(tmppath);
		goto fail;
	}
	if(close(tmpfd) != 0) {
		saved = errno;
		unlink(tmppath);
		goto fail;
	}
	if(age_move(tmppath, outp, overwrite) != 0) {
		saved = errno;
		unlink(tmppath);
		if(saved == EEXIST) {
			strncpy(errbuf, "output already exists", errcap - 1);
			errbuf[errcap - 1] = '\0';
			return -1;
		}
		goto fail;
	}
	return 0;
fail:
	strncpy(errbuf, strerror(saved), errcap - 1);
	errbuf[errcap - 1] = '\0';
	return -1;
}

/* Abandon a temp file without touching the destination. */
static void
discard_output(int tmpfd, const char *tmppath)
{
	close(tmpfd);
	unlink(tmppath);
}

/* ---- write keyfile (secrets stay in C) ---- */

SEXP
age_c_identity_write(SEXP ext, SEXP path, SEXP created, SEXP overwrite)
{
	AgeIdentities *id;
	R_xlen_t i;
	uchar pub[32];
	char publabel[] = "age";
	char privlabel[] = "age-secret-key-";
	char pubbech[PUBKEYLEN + 1];
	char privbech[PRIVKEYLEN + 1];
	char line[128 + PUBKEYLEN + PRIVKEYLEN];
	const char *ts, *outp;
	char *tmppath, msg[256];
	int tmpfd, j, n;

	id = id_addr(ext);
	if(id == NULL || id->keys == NULL)
		return result_err("identity", "invalid or freed identity");
	ts = CHAR(STRING_ELT(created, 0));
	outp = CHAR(STRING_ELT(path, 0));

	tmppath = malloc(strlen(outp) + 24);
	if(tmppath == NULL)
		return result_err("io", "out of memory");
	tmpfd = age_open_temp(outp, tmppath, strlen(outp) + 24);   /* mode 0600 */
	if(tmpfd == -1) {
		strncpy(msg, strerror(errno), sizeof(msg) - 1);
		msg[sizeof(msg) - 1] = '\0';
		free(tmppath);
		return result_err("io", msg);
	}
	for(i = 0; i < id->n; i++) {
		if(!x25519pub(pub, id->keys + i * 32) ||
		   !bech32encode(publabel, pub, 32, (uchar *)pubbech) ||
		   !bech32encode(privlabel, id->keys + i * 32, 32, (uchar *)privbech)) {
			discard_output(tmpfd, tmppath);
			free(tmppath);
			return result_err("identity", "failed to encode key");
		}
		for(j = 0; privbech[j] != '\0'; j++)
			privbech[j] = (char)toupper((unsigned char)privbech[j]);
		n = snprintf(line, sizeof(line), "# created: %s\n# public key: %s\n%s\n",
				ts, pubbech, privbech);
		if(n < 0 || (usize)n >= sizeof(line) ||
		   writeall(tmpfd, line, (usize)n) == -1) {
			wipe(line, sizeof(line));
			wipe(privbech, sizeof(privbech));
			discard_output(tmpfd, tmppath);
			free(tmppath);
			return result_err("io", "failed to write key file");
		}
	}
	wipe(line, sizeof(line));
	wipe(privbech, sizeof(privbech));
	wipe(pub, sizeof(pub));
	if(commit_output(tmpfd, tmppath, outp, Rf_asLogical(overwrite) == 1,
			msg, sizeof(msg)) != 0) {
		free(tmppath);
		return result_err("io", msg);
	}
	free(tmppath);
	return result_ok(Rf_ScalarLogical(1));
}

/* ---- explicit early scrub ---- */

SEXP
age_c_identity_free(SEXP ext)
{
	id_finalizer(ext);
	return R_NilValue;
}

/* ---- raw encrypt / decrypt ---- */

SEXP
age_c_encrypt(SEXP data, SEXP recipients, SEXP armor)
{
	uchar *recs = NULL;
	R_xlen_t nrec = 0;
	const char *e;
	int vin, vout;
	Ibuf ib;
	Obuf ob;
	usize olen;
	uchar *odata;
	SEXP res, out;

	e = parse_recipients(recipients, &recs, &nrec);
	if(e != NULL)
		return result_err("recipient", e);

	vin = memopen_read(RAW(data), (usize)XLENGTH(data));
	vout = memopen_write();
	if(vin == -1 || vout == -1) {
		if(vin != -1) memclose(vin);
		if(vout != -1) memclose(vout);
		free(recs);
		return result_err("internal", "failed to allocate buffer");
	}
	ibinit(&ib, vin);
	ib.recording = 0;                 /* MAC recording is a decrypt-only concern */
	ob.fd = vout;
	ob.cur = 0;
	ob.isarmor = Rf_asLogical(armor) == 1;

	e = age_encipher(&ib, &ob, recs, nrec);
	if(e != NULL) {
		char msg[EBUFSIZE];
		strncpy(msg, e, sizeof(msg) - 1);
		msg[sizeof(msg) - 1] = '\0';
		wipe(&ob, sizeof(ob));
		ibfree(&ib);
		memclose(vin);
		memclose(vout);
		free(recs);
		return result_err("encrypt", msg);
	}
	odata = memdata(vout, &olen);
	res = PROTECT(Rf_allocVector(RAWSXP, olen));
	if(olen > 0)
		memcpy(RAW(res), odata, olen);
	out = result_ok(res);
	UNPROTECT(1);
	wipe(&ob, sizeof(ob));
	ibfree(&ib);
	memclose(vin);
	memclose(vout);
	free(recs);
	return out;
}

SEXP
age_c_decrypt(SEXP data, SEXP ext)
{
	AgeIdentities *id;
	const char *e;
	int vin, vout;
	Ibuf ib;
	Obuf ob;
	usize olen;
	uchar *odata;
	SEXP res, out;

	id = id_addr(ext);
	if(id == NULL || id->keys == NULL)
		return result_err("identity", "invalid or freed identity");

	vin = memopen_read(RAW(data), (usize)XLENGTH(data));
	vout = memopen_write();
	if(vin == -1 || vout == -1) {
		if(vin != -1) memclose(vin);
		if(vout != -1) memclose(vout);
		return result_err("internal", "failed to allocate buffer");
	}
	ibinit(&ib, vin);
	ob.fd = vout;
	ob.cur = 0;
	ob.isarmor = 0;

	e = age_decipher(&ib, &ob, id->keys, id->n);
	if(e != NULL) {
		char msg[EBUFSIZE];
		strncpy(msg, e, sizeof(msg) - 1);
		msg[sizeof(msg) - 1] = '\0';
		wipe(&ob, sizeof(ob));
		ibfree(&ib);
		memclose(vin);
		memclose(vout);
		return result_err("decrypt", msg);
	}
	odata = memdata(vout, &olen);
	res = PROTECT(Rf_allocVector(RAWSXP, olen));
	if(olen > 0)
		memcpy(RAW(res), odata, olen);
	out = result_ok(res);
	UNPROTECT(1);
	wipe(&ob, sizeof(ob));
	ibfree(&ib);
	memclose(vin);
	memclose(vout);
	return out;
}

/* ---- file encrypt / decrypt (streamed through an atomic temp file) ---- */

typedef const char *(*transform_fn)(Ibuf *in, Obuf *out, void *ctx);

/*
 * Stream a file transform: read `inp`, write into a private temp file next to
 * `outp`, and rename the temp into place only after `fn` fully succeeds. The
 * destination is therefore never truncated up front, never shows a partial
 * result, and survives untouched on any failure. `recording` sets Ibuf MAC
 * recording (0 encrypt, 1 decrypt); `isarmor` sets Obuf armoring; `overwrite`
 * controls whether an existing destination may be replaced.
 */
static SEXP
run_file_transform(const char *inp, const char *outp, int isarmor, int recording,
		int overwrite, transform_fn fn, void *ctx, const char *fail_class)
{
	char *tmppath, msg[256];
	int infd, tmpfd;
	Ibuf ib;
	Obuf ob;
	const char *e;

	tmppath = malloc(strlen(outp) + 24);
	if(tmppath == NULL)
		return result_err("io", "out of memory");
	infd = open(inp, O_RDONLY | O_BINARY);
	if(infd == -1) {
		strncpy(msg, strerror(errno), sizeof(msg) - 1);
		msg[sizeof(msg) - 1] = '\0';
		free(tmppath);
		return result_err("io", msg);
	}
	tmpfd = age_open_temp(outp, tmppath, strlen(outp) + 24);
	if(tmpfd == -1) {
		strncpy(msg, strerror(errno), sizeof(msg) - 1);
		msg[sizeof(msg) - 1] = '\0';
		close(infd);
		free(tmppath);
		return result_err("io", msg);
	}
	ibinit(&ib, infd);
	ib.recording = recording;
	ob.fd = tmpfd;
	ob.cur = 0;
	ob.isarmor = isarmor;

	e = fn(&ib, &ob, ctx);
	if(e != NULL) {                 /* copy before any call can touch ebuf */
		strncpy(msg, e, sizeof(msg) - 1);
		msg[sizeof(msg) - 1] = '\0';
	}
	wipe(&ob, sizeof(ob));
	ibfree(&ib);
	close(infd);
	if(e != NULL) {
		discard_output(tmpfd, tmppath);
		free(tmppath);
		return result_err(fail_class, msg);
	}
	if(commit_output(tmpfd, tmppath, outp, overwrite, msg, sizeof(msg)) != 0) {
		free(tmppath);
		return result_err("io", msg);
	}
	free(tmppath);
	return result_ok(Rf_ScalarLogical(1));
}

struct enc_ctx { const uchar *recs; R_xlen_t nrec; };
static const char *
tf_encrypt(Ibuf *in, Obuf *out, void *c)
{
	struct enc_ctx *x = c;
	return age_encipher(in, out, x->recs, x->nrec);
}

struct dec_ctx { const uchar *keys; R_xlen_t n; };
static const char *
tf_decrypt(Ibuf *in, Obuf *out, void *c)
{
	struct dec_ctx *x = c;
	return age_decipher(in, out, x->keys, x->n);
}

struct encp_ctx { const char *pass; uint cost; };
static const char *
tf_encrypt_pass(Ibuf *in, Obuf *out, void *c)
{
	struct encp_ctx *x = c;
	return age_encipher_passphrase(in, out, x->pass, x->cost);
}

struct decp_ctx { const char *pass; };
static const char *
tf_decrypt_pass(Ibuf *in, Obuf *out, void *c)
{
	struct decp_ctx *x = c;
	return age_decipher_passphrase(in, out, x->pass);
}

SEXP
age_c_encrypt_path(SEXP inpath, SEXP outpath, SEXP recipients, SEXP armor,
		SEXP overwrite)
{
	uchar *recs = NULL;
	R_xlen_t nrec = 0;
	const char *e;
	struct enc_ctx ctx;
	SEXP out;

	e = parse_recipients(recipients, &recs, &nrec);
	if(e != NULL)
		return result_err("recipient", e);
	ctx.recs = recs;
	ctx.nrec = nrec;
	out = run_file_transform(CHAR(STRING_ELT(inpath, 0)),
			CHAR(STRING_ELT(outpath, 0)),
			Rf_asLogical(armor) == 1, 0, Rf_asLogical(overwrite) == 1,
			tf_encrypt, &ctx, "encrypt");
	free(recs);
	return out;
}

SEXP
age_c_decrypt_path(SEXP inpath, SEXP outpath, SEXP ext, SEXP overwrite)
{
	AgeIdentities *id;
	struct dec_ctx ctx;

	id = id_addr(ext);
	if(id == NULL || id->keys == NULL)
		return result_err("identity", "invalid or freed identity");
	ctx.keys = id->keys;
	ctx.n = id->n;
	return run_file_transform(CHAR(STRING_ELT(inpath, 0)),
			CHAR(STRING_ELT(outpath, 0)),
			0, 1, Rf_asLogical(overwrite) == 1, tf_decrypt, &ctx, "decrypt");
}

/* ---- passphrase (scrypt) encrypt / decrypt ---- */

SEXP
age_c_encrypt_passphrase(SEXP data, SEXP pass, SEXP armor, SEXP logn)
{
	const char *e, *p;
	int vin, vout;
	Ibuf ib;
	Obuf ob;
	usize olen;
	uchar *odata;
	SEXP res, out;

	p = CHAR(STRING_ELT(pass, 0));
	vin = memopen_read(RAW(data), (usize)XLENGTH(data));
	vout = memopen_write();
	if(vin == -1 || vout == -1) {
		if(vin != -1) memclose(vin);
		if(vout != -1) memclose(vout);
		return result_err("internal", "failed to allocate buffer");
	}
	ibinit(&ib, vin);
	ib.recording = 0;
	ob.fd = vout;
	ob.cur = 0;
	ob.isarmor = Rf_asLogical(armor) == 1;

	e = age_encipher_passphrase(&ib, &ob, p, (uint)Rf_asInteger(logn));
	if(e != NULL) {
		char msg[EBUFSIZE];
		strncpy(msg, e, sizeof(msg) - 1);
		msg[sizeof(msg) - 1] = '\0';
		wipe(&ob, sizeof(ob));
		ibfree(&ib);
		memclose(vin);
		memclose(vout);
		return result_err("encrypt", msg);
	}
	odata = memdata(vout, &olen);
	res = PROTECT(Rf_allocVector(RAWSXP, olen));
	if(olen > 0)
		memcpy(RAW(res), odata, olen);
	out = result_ok(res);
	UNPROTECT(1);
	wipe(&ob, sizeof(ob));
	ibfree(&ib);
	memclose(vin);
	memclose(vout);
	return out;
}

SEXP
age_c_decrypt_passphrase(SEXP data, SEXP pass)
{
	const char *e, *p;
	int vin, vout;
	Ibuf ib;
	Obuf ob;
	usize olen;
	uchar *odata;
	SEXP res, out;

	p = CHAR(STRING_ELT(pass, 0));
	vin = memopen_read(RAW(data), (usize)XLENGTH(data));
	vout = memopen_write();
	if(vin == -1 || vout == -1) {
		if(vin != -1) memclose(vin);
		if(vout != -1) memclose(vout);
		return result_err("internal", "failed to allocate buffer");
	}
	ibinit(&ib, vin);
	ob.fd = vout;
	ob.cur = 0;
	ob.isarmor = 0;

	e = age_decipher_passphrase(&ib, &ob, p);
	if(e != NULL) {
		char msg[EBUFSIZE];
		strncpy(msg, e, sizeof(msg) - 1);
		msg[sizeof(msg) - 1] = '\0';
		wipe(&ob, sizeof(ob));
		ibfree(&ib);
		memclose(vin);
		memclose(vout);
		return result_err("decrypt", msg);
	}
	odata = memdata(vout, &olen);
	res = PROTECT(Rf_allocVector(RAWSXP, olen));
	if(olen > 0)
		memcpy(RAW(res), odata, olen);
	out = result_ok(res);
	UNPROTECT(1);
	wipe(&ob, sizeof(ob));
	ibfree(&ib);
	memclose(vin);
	memclose(vout);
	return out;
}

SEXP
age_c_encrypt_path_passphrase(SEXP inpath, SEXP outpath, SEXP pass, SEXP armor,
		SEXP logn, SEXP overwrite)
{
	struct encp_ctx ctx;

	ctx.pass = CHAR(STRING_ELT(pass, 0));
	ctx.cost = (uint)Rf_asInteger(logn);
	return run_file_transform(CHAR(STRING_ELT(inpath, 0)),
			CHAR(STRING_ELT(outpath, 0)),
			Rf_asLogical(armor) == 1, 0, Rf_asLogical(overwrite) == 1,
			tf_encrypt_pass, &ctx, "encrypt");
}

SEXP
age_c_decrypt_path_passphrase(SEXP inpath, SEXP outpath, SEXP pass, SEXP overwrite)
{
	struct decp_ctx ctx;

	ctx.pass = CHAR(STRING_ELT(pass, 0));
	return run_file_transform(CHAR(STRING_ELT(inpath, 0)),
			CHAR(STRING_ELT(outpath, 0)),
			0, 1, Rf_asLogical(overwrite) == 1, tf_decrypt_pass, &ctx, "decrypt");
}
