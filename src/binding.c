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
 * is effectively operation-local under R. Every entry point calls eclear()
 * first so no message survives into the next operation. Do not call this code
 * from multiple threads or re-enter it from a callback without first making
 * that state operation-local.
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
#include "platform.h"

/* O_BINARY suppresses CRLF/Ctrl-Z translation when reading ciphertext on
   Windows; it does not exist on POSIX, where file I/O is already binary. */
#ifndef O_BINARY
#define O_BINARY 0
#endif

#define PUBKEYLEN  62   /* "age1..." recipient string length          */
#define PRIVKEYLEN 74   /* "AGE-SECRET-KEY-1..." identity string length */

/*
 * scrypt work-factor bounds. agec's wrapkey() computes `1 << cost` on an int,
 * which is undefined for cost >= 31, so the bound is enforced here as well as
 * in R: the R layer is the only caller in practice, but a .Call() straight to
 * the registered symbol must not reach undefined behaviour. The upper bound
 * matches SCRYPTMAXCOST in src/agec/agecore.c, which guards the decrypt side.
 */
#define SCRYPT_MINCOST 2
#define SCRYPT_MAXCOST 22

/* Key files hold a handful of short lines; cap what we will read. */
#define KEYFILE_MAX (1024 * 1024)

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

/* Copy into a caller-owned buffer; agec error strings point into ebuf. */
static void
copyerr(char *dst, usize cap, const char *src)
{
	strncpy(dst, src, cap - 1);
	dst[cap - 1] = '\0';
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
 * The type check matters: STRING_ELT() on a non-character vector raises an R
 * error, which would longjmp straight past the free() below.
 */
static const char *
parse_recipients(SEXP recipients, uchar **out, R_xlen_t *nout)
{
	R_xlen_t nrec, i;
	uchar *recs;
	char bech[PUBKEYLEN + 1];

	*out = NULL;
	if(TYPEOF(recipients) != STRSXP)
		return "recipients must be a character vector";
	nrec = XLENGTH(recipients);
	if(nrec == 0)
		return "no recipients supplied";
	recs = malloc((usize)nrec * 32);
	if(recs == NULL)
		return "out of memory";
	for(i = 0; i < nrec; i++) {
		SEXP el = STRING_ELT(recipients, i);
		const char *s;
		if(el == NA_STRING) {
			free(recs);
			return "invalid recipient string";
		}
		s = CHAR(el);
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

/* ---- identity key collection ---- */

/*
 * A growable array of 32-byte private keys. Key files can hold any number of
 * identities, so the array is sized as they are parsed rather than up front.
 */
struct keybuf {
	uchar    *keys;
	R_xlen_t  n, cap;
};

static void
keybuf_free(struct keybuf *kb)
{
	if(kb->keys != NULL) {
		wipe(kb->keys, (usize)kb->cap * 32);
		free(kb->keys);
	}
	kb->keys = NULL;
	kb->n = kb->cap = 0;
}

/*
 * Decode one "AGE-SECRET-KEY-1..." string and append it.
 * Returns 1 on success, 0 if the string is not a valid identity, -1 on OOM.
 */
static int
keybuf_push(struct keybuf *kb, const char *s)
{
	char bech[PRIVKEYLEN + 1];
	uchar *p;
	int ok;

	if(strlen(s) != PRIVKEYLEN)
		return 0;
	if(kb->n == kb->cap) {
		R_xlen_t ncap = kb->cap ? kb->cap * 2 : 4;
		p = realloc(kb->keys, (usize)ncap * 32);
		if(p == NULL)
			return -1;
		kb->keys = p;
		kb->cap = ncap;
	}
	memcpy(bech, s, PRIVKEYLEN);
	bech[PRIVKEYLEN] = '\0';
	ok = x25519privkey(bech, kb->keys + kb->n * 32);
	wipe(bech, sizeof(bech));            /* holds a secret on every path */
	if(!ok)
		return 0;
	kb->n++;
	return 1;
}

/* Strip leading/trailing ASCII whitespace in place. */
static char *
trimline(char *s)
{
	char *e;

	while(*s == ' ' || *s == '\t' || *s == '\r')
		s++;
	e = s + strlen(s);
	while(e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'))
		e--;
	*e = '\0';
	return s;
}

/*
 * Read a whole key file into a malloc'd, NUL-terminated buffer.
 * Returns the buffer (caller wipes and frees) or NULL with msg set.
 */
static char *
slurp_keyfile(const char *path, usize *lenout, char *msg, usize msgcap)
{
	char *buf, *p;
	usize cap, len;
	ssize nr;
	int fd;

	fd = open(path, O_RDONLY | O_BINARY);
	if(fd == -1) {
		copyerr(msg, msgcap, strerror(errno));
		return NULL;
	}
	cap = 4096;
	len = 0;
	buf = malloc(cap);
	if(buf == NULL) {
		close(fd);
		copyerr(msg, msgcap, "out of memory");
		return NULL;
	}
	for(;;) {
		if(len >= KEYFILE_MAX) {
			wipe(buf, cap);
			free(buf);
			close(fd);
			copyerr(msg, msgcap, "key file is too large");
			return NULL;
		}
		if(len == cap - 1) {
			p = realloc(buf, cap * 2);
			if(p == NULL) {
				wipe(buf, cap);
				free(buf);
				close(fd);
				copyerr(msg, msgcap, "out of memory");
				return NULL;
			}
			buf = p;
			cap *= 2;
		}
		nr = read(fd, buf + len, cap - 1 - len);
		if(nr == -1) {
			copyerr(msg, msgcap, strerror(errno));
			wipe(buf, cap);
			free(buf);
			close(fd);
			return NULL;
		}
		if(nr == 0)
			break;
		len += (usize)nr;
	}
	close(fd);
	buf[len] = '\0';
	*lenout = cap;                       /* wipe the whole allocation */
	return buf;
}

/*
 * Parse every identity in a key file, appending to `kb`. The file's bytes are
 * read, scanned and scrubbed entirely in C: secrets loaded from disk must not
 * pass through R, whose CHARSXP cache would retain them for the life of the
 * session. Returns 1 on success, 0 with msg set on failure.
 */
static int
scan_keyfile(const char *path, struct keybuf *kb, char *msg, usize msgcap)
{
	char *buf, *line, *next, *t;
	usize cap;
	R_xlen_t before = kb->n;
	int rc, ok = 0;

	buf = slurp_keyfile(path, &cap, msg, msgcap);
	if(buf == NULL)
		return 0;
	for(line = buf; line != NULL; line = next) {
		next = strchr(line, '\n');
		if(next != NULL)
			*next++ = '\0';
		t = trimline(line);
		/*
		 * An encrypted key file is itself an age file; refuse it with a
		 * clear message rather than reporting "no identities".
		 */
		if(strncmp(t, "-----BEGIN AGE", 14) == 0 ||
		   strstr(t, "age-encryption.org/v1") != NULL) {
			copyerr(msg, msgcap,
				"passphrase-encrypted key files are not supported");
			goto out;
		}
		if(strncmp(t, "AGE-SECRET-KEY-1", 16) != 0)
			continue;                /* comments, blank lines, pubkeys */
		rc = keybuf_push(kb, t);
		if(rc == -1) {
			copyerr(msg, msgcap, "out of memory");
			goto out;
		}
		if(rc == 0) {
			copyerr(msg, msgcap, "failed to parse identity in key file");
			goto out;
		}
	}
	if(kb->n == before) {
		copyerr(msg, msgcap, "no age identities in key file");
		goto out;
	}
	ok = 1;
out:
	wipe(buf, cap);
	free(buf);
	return ok;
}

/* ---- keygen ---- */

SEXP
age_c_keygen(void)
{
	uchar priv[32], pub[32];
	AgeIdentities *id;

	eclear();
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

/*
 * `items` holds inline "AGE-SECRET-KEY-1..." strings and key-file paths;
 * `isfile` marks which is which, elementwise, so the original order is kept
 * (identities are tried in order on decrypt). Key files are read here in C.
 */
SEXP
age_c_identity_parse(SEXP items, SEXP isfile)
{
	struct keybuf kb = { NULL, 0, 0 };
	AgeIdentities *id;
	R_xlen_t n, i;
	char msg[512];
	const int *file;
	int rc;

	eclear();
	if(TYPEOF(items) != STRSXP || TYPEOF(isfile) != LGLSXP)
		return result_err("identity", "invalid identity input");
	n = XLENGTH(items);
	if(n == 0 || XLENGTH(isfile) != n)
		return result_err("identity", "no identities supplied");
	file = LOGICAL(isfile);

	for(i = 0; i < n; i++) {
		SEXP el = STRING_ELT(items, i);
		const char *s;

		if(el == NA_STRING || file[i] == NA_LOGICAL) {
			keybuf_free(&kb);
			return result_err("identity", "invalid identity string");
		}
		s = CHAR(el);
		if(file[i]) {
			if(!scan_keyfile(s, &kb, msg, sizeof(msg))) {
				keybuf_free(&kb);
				return result_err("identity", msg);
			}
			continue;
		}
		rc = keybuf_push(&kb, s);
		if(rc == -1) {
			keybuf_free(&kb);
			return result_err("identity", "out of memory");
		}
		if(rc == 0) {
			keybuf_free(&kb);
			return result_err("identity", "failed to parse identity");
		}
	}
	if(kb.n == 0) {
		keybuf_free(&kb);
		return result_err("identity", "no identities found");
	}
	id = malloc(sizeof(*id));
	if(id == NULL) {
		keybuf_free(&kb);
		return result_err("identity", "out of memory");
	}
	id->keys = kb.keys;                  /* ownership moves to the identity */
	id->n = kb.n;
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

	eclear();
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
			copyerr(errbuf, errcap, "output already exists");
			return -1;
		}
		goto fail;
	}
	return 0;
fail:
	copyerr(errbuf, errcap, strerror(saved));
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

	eclear();
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
		copyerr(msg, sizeof(msg), strerror(errno));
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

/* ---- in-memory operation teardown ---- */

/*
 * The four raw entry points share one tail: copy the sink into a fresh raw
 * vector, then close and scrub everything. Building the result allocates, and
 * an R allocation failure unwinds -- which would leak the two memfd slots.
 * memtab holds only MEMFD_MAX of them, so a handful of such failures would
 * wedge the backend for the rest of the session. R_UnwindProtect runs the
 * teardown on that path too.
 */
struct mem_teardown {
	int   vin, vout;
	Ibuf *ib;
	Obuf *ob;
};

static void
mem_clean(void *data, Rboolean jump)
{
	struct mem_teardown *c = data;

	(void)jump;                          /* same teardown either way */
	wipe(c->ob, sizeof(*c->ob));
	ibfree(c->ib);
	memclose(c->vin);
	memclose(c->vout);
}

static SEXP
mem_body(void *data)
{
	struct mem_teardown *c = data;
	usize olen;
	uchar *odata;
	SEXP res, out;

	odata = memdata(c->vout, &olen);
	res = PROTECT(Rf_allocVector(RAWSXP, olen));
	if(olen > 0)
		memcpy(RAW(res), odata, olen);
	out = result_ok(res);
	UNPROTECT(1);
	return out;
}

static SEXP
mem_finish(int vin, int vout, Ibuf *ib, Obuf *ob)
{
	struct mem_teardown c;
	SEXP cont, out;

	c.vin = vin;
	c.vout = vout;
	c.ib = ib;
	c.ob = ob;
	cont = PROTECT(R_MakeUnwindCont());
	out = R_UnwindProtect(mem_body, &c, mem_clean, &c, cont);
	UNPROTECT(1);
	return out;
}

/* Tear down, then build the error result (no allocation before cleanup). */
static SEXP
mem_fail(int vin, int vout, Ibuf *ib, Obuf *ob, const char *cls, const char *e)
{
	struct mem_teardown c;
	char msg[EBUFSIZE];

	copyerr(msg, sizeof(msg), e);
	c.vin = vin;
	c.vout = vout;
	c.ib = ib;
	c.ob = ob;
	mem_clean(&c, FALSE);
	return result_err(cls, msg);
}

/* ---- raw encrypt / decrypt ---- */

SEXP
age_c_encrypt(SEXP data, SEXP recipients, SEXP armor)
{
	uchar *recs = NULL;
	R_xlen_t nrec = 0;
	const uchar *din;
	usize dlen;
	const char *e;
	int vin, vout;
	Ibuf ib;
	Obuf ob;

	eclear();
	/*
	 * Touch the payload before anything is allocated: RAW() raises an R
	 * error on a non-raw input, and that longjmp must not skip free(recs).
	 */
	din = RAW(data);
	dlen = (usize)XLENGTH(data);

	e = parse_recipients(recipients, &recs, &nrec);
	if(e != NULL)
		return result_err("recipient", e);

	vin = memopen_read(din, dlen);
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
	free(recs);
	if(e != NULL)
		return mem_fail(vin, vout, &ib, &ob, "encrypt", e);
	return mem_finish(vin, vout, &ib, &ob);
}

SEXP
age_c_decrypt(SEXP data, SEXP ext)
{
	AgeIdentities *id;
	const uchar *din;
	usize dlen;
	const char *e;
	int vin, vout;
	Ibuf ib;
	Obuf ob;

	eclear();
	din = RAW(data);
	dlen = (usize)XLENGTH(data);

	id = id_addr(ext);
	if(id == NULL || id->keys == NULL)
		return result_err("identity", "invalid or freed identity");

	vin = memopen_read(din, dlen);
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
	if(e != NULL)
		return mem_fail(vin, vout, &ib, &ob, "decrypt", e);
	return mem_finish(vin, vout, &ib, &ob);
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
		copyerr(msg, sizeof(msg), strerror(errno));
		free(tmppath);
		return result_err("io", msg);
	}
	tmpfd = age_open_temp(outp, tmppath, strlen(outp) + 24);
	if(tmpfd == -1) {
		copyerr(msg, sizeof(msg), strerror(errno));
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
	if(e != NULL)                   /* copy before any call can touch ebuf */
		copyerr(msg, sizeof(msg), e);
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
	const char *e, *inp, *outp;
	struct enc_ctx ctx;
	SEXP out;

	eclear();
	/* Resolve both paths before malloc'ing: CHAR()/STRING_ELT() can raise. */
	inp = CHAR(STRING_ELT(inpath, 0));
	outp = CHAR(STRING_ELT(outpath, 0));

	e = parse_recipients(recipients, &recs, &nrec);
	if(e != NULL)
		return result_err("recipient", e);
	ctx.recs = recs;
	ctx.nrec = nrec;
	out = run_file_transform(inp, outp,
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

	eclear();
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

/* See SCRYPT_MINCOST/SCRYPT_MAXCOST: out of range, `1 << cost` would be UB. */
static int
check_cost(SEXP logn, uint *cost)
{
	int v = Rf_asInteger(logn);

	if(v == NA_INTEGER || v < SCRYPT_MINCOST || v > SCRYPT_MAXCOST)
		return 0;
	*cost = (uint)v;
	return 1;
}

SEXP
age_c_encrypt_passphrase(SEXP data, SEXP pass, SEXP armor, SEXP logn)
{
	const char *e, *p;
	const uchar *din;
	usize dlen;
	uint cost;
	int vin, vout;
	Ibuf ib;
	Obuf ob;

	eclear();
	din = RAW(data);
	dlen = (usize)XLENGTH(data);
	if(!check_cost(logn, &cost))
		return result_err("encrypt", "scrypt work factor out of range");
	p = CHAR(STRING_ELT(pass, 0));

	vin = memopen_read(din, dlen);
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

	e = age_encipher_passphrase(&ib, &ob, p, cost);
	if(e != NULL)
		return mem_fail(vin, vout, &ib, &ob, "encrypt", e);
	return mem_finish(vin, vout, &ib, &ob);
}

SEXP
age_c_decrypt_passphrase(SEXP data, SEXP pass)
{
	const char *e, *p;
	const uchar *din;
	usize dlen;
	int vin, vout;
	Ibuf ib;
	Obuf ob;

	eclear();
	din = RAW(data);
	dlen = (usize)XLENGTH(data);
	p = CHAR(STRING_ELT(pass, 0));

	vin = memopen_read(din, dlen);
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
	if(e != NULL)
		return mem_fail(vin, vout, &ib, &ob, "decrypt", e);
	return mem_finish(vin, vout, &ib, &ob);
}

SEXP
age_c_encrypt_path_passphrase(SEXP inpath, SEXP outpath, SEXP pass, SEXP armor,
		SEXP logn, SEXP overwrite)
{
	struct encp_ctx ctx;

	eclear();
	if(!check_cost(logn, &ctx.cost))
		return result_err("encrypt", "scrypt work factor out of range");
	ctx.pass = CHAR(STRING_ELT(pass, 0));
	return run_file_transform(CHAR(STRING_ELT(inpath, 0)),
			CHAR(STRING_ELT(outpath, 0)),
			Rf_asLogical(armor) == 1, 0, Rf_asLogical(overwrite) == 1,
			tf_encrypt_pass, &ctx, "encrypt");
}

SEXP
age_c_decrypt_path_passphrase(SEXP inpath, SEXP outpath, SEXP pass, SEXP overwrite)
{
	struct decp_ctx ctx;

	eclear();
	ctx.pass = CHAR(STRING_ELT(pass, 0));
	return run_file_transform(CHAR(STRING_ELT(inpath, 0)),
			CHAR(STRING_ELT(outpath, 0)),
			0, 1, Rf_asLogical(overwrite) == 1, tf_decrypt_pass, &ctx, "decrypt");
}
