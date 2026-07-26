#include "agec.h"
#include "agecore.h"

/* Reject scrypt work factors above this on decrypt (matches agec's CLI). */
#define SCRYPTMAXCOST 22

/*
 * Adapted from the static encipher()/decipher() machinery in agec.c. The only
 * substantive change is that identities/recipients are passed as flat 32-byte
 * key arrays instead of the CLI's Keys struct, and scrypt stanzas are rejected
 * (no interactive passphrase prompt in a library context).
 */

/* Constant-time equality, so MAC verification does not leak a timing signal. */
static int
ct_eq(const uchar *a, const uchar *b, usize n)
{
	uchar d = 0;
	usize i;

	for(i = 0; i < n; i++)
		d |= (uchar)(a[i] ^ b[i]);
	return d == 0;
}

/* ---- encrypt ---- */

static const char *
mkfilekey(uchar filekey[16])
{
	if(randombuf(filekey, 16) == 0)
		return "failed to generate file key";
	return NULL;
}

static const char *
payload(uchar filekey[16], Ibuf *in, Obuf *out)
{
	uchar plkey[32], plnonce[16];
	const char *e;
	ssize nw;

	if(randombuf(plnonce, 16) == 0)
		return "failed to generate payload nonce";
	payloadkey(filekey, plnonce, plkey);
	nw = bwrite(out, plnonce, sizeof(plnonce));
	if(nw == -1)
		return eget();
	e = plencrypt(in, out, plkey);
	wipe(plkey, sizeof(plkey));
	return e;
}

static const char *
pubenc(Header *h, uchar filekey[16], const uchar *recs, usize nrec)
{
	const char *e;
	usize i;

	for(i = 0; i < nrec; i++) {
		e = x25519stanza(h, filekey, (uchar *)(recs + i * 32));
		if(e)
			return e;
	}
	return NULL;
}

static const char *
finish_hdr(Header *h, uchar filekey[16])
{
	char mac[B64EBUFLEN(32) + 1];
	const char *e;
	usize maclen;

	e = hdrappend(h, "---");
	if(e)
		return e;
	hdrmac(h->data, h->len, filekey, mac, &maclen);
	mac[sizeof(mac) - 1] = '\0';
	return hdrappend(h, " %s\n", mac);
}

static const char *
genhdr(Header *h, uchar filekey[16], const uchar *recs, usize nrec)
{
	const char *e;

	e = hdrappend(h, "age-encryption.org/v1\n");
	if(e)
		return e;
	e = pubenc(h, filekey, recs, nrec);
	if(e)
		return e;
	return finish_hdr(h, filekey);
}

static const char *
genhdr_pass(Header *h, uchar filekey[16], const char *pass, uint cost)
{
	const char *e;

	e = hdrappend(h, "age-encryption.org/v1\n");
	if(e)
		return e;
	e = scryptstanzacost(h, filekey, (char *)pass, cost);
	if(e)
		return e;
	return finish_hdr(h, filekey);
}

static const char *
writehdr(Obuf *out, Header *h)
{
	ssize nw;

	if(out->isarmor) {
		nw = writeall(out->fd, armorfirst, sizeof(armorfirst) - 1);
		if(nw == -1)
			return eget();
	}
	nw = bwrite(out, h->data, h->len);
	if(nw == -1)
		return eget();
	return NULL;
}

static const char *
writebody(Obuf *out, Ibuf *in, uchar filekey[16])
{
	const char *e;
	ssize nw;

	e = payload(filekey, in, out);
	if(e)
		return e;
	if(bflush(out) == -1)
		return eget();
	if(out->isarmor) {
		nw = writeall(out->fd, armorlast, sizeof(armorlast) - 1);
		if(nw == -1)
			return eget();
	}
	return NULL;
}

/* Write a fully-built header and the encrypted payload. */
static const char *
writeall_out(Ibuf *in, Obuf *out, Header *h, uchar filekey[16])
{
	const char *e;

	e = writehdr(out, h);
	if(e)
		return ewrap("failed to encrypt", e);
	e = writebody(out, in, filekey);
	if(e)
		return ewrap("failed to encrypt", e);
	return NULL;
}

const char *
age_encipher(Ibuf *in, Obuf *out, const uchar *recs, usize nrec)
{
	Header h;
	uchar filekey[16];
	const char *e;

	e = mkfilekey(filekey);
	if(e) {
		wipe(filekey, sizeof(filekey));
		return e;
	}
	e = hdrinit(&h);
	if(e) {
		wipe(filekey, sizeof(filekey));
		return ewrap("failed to generate header", e);
	}
	e = genhdr(&h, filekey, recs, nrec);
	if(e)
		e = ewrap("failed to generate header", e);
	else
		e = writeall_out(in, out, &h, filekey);
	wipe(filekey, sizeof(filekey));
	free(h.data);
	return e;
}

const char *
age_encipher_passphrase(Ibuf *in, Obuf *out, const char *pass, uint cost)
{
	Header h;
	uchar filekey[16];
	const char *e;

	e = mkfilekey(filekey);
	if(e) {
		wipe(filekey, sizeof(filekey));
		return e;
	}
	e = hdrinit(&h);
	if(e) {
		wipe(filekey, sizeof(filekey));
		return ewrap("failed to generate header", e);
	}
	e = genhdr_pass(&h, filekey, pass, cost);
	if(e)
		e = ewrap("failed to generate header", e);
	else
		e = writeall_out(in, out, &h, filekey);
	wipe(filekey, sizeof(filekey));
	free(h.data);
	return e;
}

/* ---- decrypt ---- */

static const char *
validmac(Ibuf *in, uchar filekey[16], int *isvalid)
{
	uchar mac1[32], mac2[32];
	const char *e;
	uchar *data;
	usize len;

	data = recstop(in, &len);
	if(data == NULL)
		return eget();
	e = getmac(in, mac1);
	if(e)
		return e;
	mac(data, len, filekey, mac2);
	*isvalid = ct_eq(mac1, mac2, 32);
	return NULL;
}

static const char *
validatemac(Ibuf *in, uchar filekey[16])
{
	const char *e;
	int valid = 0; /* fail closed if validmac() returns without setting it */

	e = validmac(in, filekey, &valid);
	if(e)
		return ewrap("error parsing header", e);
	if(!valid)
		return "bad header MAC";
	return NULL;
}

static const char *
findx25519(uchar filekey[16], Stanza *s, const uchar *ids, usize nid, int *found)
{
	const char *e = NULL;
	usize i;

	for(i = 0; i < nid && !*found; i++) {
		*found = x25519getkey(filekey, &s->arg.x25519,
				(uchar *)(ids + i * 32), &e);
		if(e)
			return e;
	}
	return NULL;
}

/* filekey is filled if and only if an X25519 identity is found */
static const char *
match(Ibuf *in, uchar filekey[16], Stanza *s, const uchar *ids, usize nid,
		int *found)
{
	const char *e;
	int end, seenscrypt, n;

	for(n = seenscrypt = *found = 0;; n++) {
		e = getstanza(in, s, &end);
		if(e)
			return ewrap("error parsing header", e);
		if(end)
			break;
		if(s->type == SCRYPT) {
			seenscrypt = *found = 1;
		} else if(s->type == X25519 && !*found) {
			e = findx25519(filekey, s, ids, nid, found);
			if(e)
				return ewrap("failed to match identity", e);
		}
	}
	if(n > 1 && seenscrypt)
		return "invalid input: scrypt recipient is not the only one";
	return NULL;
}

/* Validate the header MAC, then decrypt and write the STREAM payload. */
static const char *
decipher_payload(Ibuf *in, Obuf *out, uchar filekey[16])
{
	const char *e;
	uchar plnonce[16], plkey[32];

	e = validatemac(in, filekey);
	if(e)
		return ewrap("failed to decrypt", e);
	e = getplnonce(in, plnonce);
	if(e)
		return ewrap("error parsing header", e);
	payloadkey(filekey, plnonce, plkey);
	e = pldecrypt(in, out, plkey);
	wipe(plkey, sizeof(plkey));
	if(e)
		return ewrap("failed to decrypt", e);
	if(bflush(out) == -1)
		return eget();
	return NULL;
}

const char *
age_decipher(Ibuf *in, Obuf *out, const uchar *ids, usize nid)
{
	const char *e;
	uchar filekey[16];
	Stanza s;
	int found;

	e = getversion(in);
	if(e)
		return ewrap("error parsing header", e);
	e = match(in, filekey, &s, ids, nid, &found);
	if(e == NULL) {
		if(found && s.type == SCRYPT)
			e = "file is passphrase-encrypted; use the *_passphrase functions";
		else if(!found)
			e = "no identity matched any of the recipients";
		else
			e = decipher_payload(in, out, filekey);
	}
	wipe(filekey, sizeof(filekey));   /* scrub on every path past match() */
	return e;
}

const char *
age_decipher_passphrase(Ibuf *in, Obuf *out, const char *pass)
{
	const char *e;
	uchar filekey[16];
	Stanza s;
	int found, ok;

	e = getversion(in);
	if(e)
		return ewrap("error parsing header", e);
	e = match(in, filekey, &s, NULL, 0, &found);
	if(e != NULL) {
		/* fall through to the wipe */
	} else if(!found || s.type != SCRYPT) {
		e = "no scrypt recipient found (file is not passphrase-encrypted)";
	} else if(s.arg.scrypt.cost > SCRYPTMAXCOST) {
		e = "scrypt work factor is too large";
	} else {
		ok = scryptgetkey(filekey, &s.arg.scrypt, (char *)pass, &e);
		if(ok)
			e = decipher_payload(in, out, filekey);
		else if(e == NULL)
			e = "incorrect passphrase";
	}
	wipe(filekey, sizeof(filekey));   /* scrub on every path past match() */
	return e;
}
