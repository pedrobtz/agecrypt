#include "common.h"
#include "crypto.h"
#include "base64.h"
#include "header.h"
#include "keyenc.h"
#include "scrypt.h"
#include "util.h"

#define SALTLEN		16
#define COST		18	/* power of two of actual cost */

static const char label[] = "age-encryption.org/v1/scrypt";

static void catlabel(uchar *s);
static const char *stanza(Header *h, uchar filekey[16], char *pass, uchar *salt, uint cost);
static const char *wrapkey(uchar key[32], char *pass, uchar *salt, uint factor);

const char *
scryptstanza(Header *h, uchar filekey[16], char *pass)
{
	return scryptstanzacost(h, filekey, pass, COST);
}

/* Like scryptstanza but with a caller-chosen work factor (log2 of N). */
const char *
scryptstanzacost(Header *h, uchar filekey[16], char *pass, uint cost)
{
	uchar salt[SALTLEN + sizeof(label) - 1];
	int ok;

	ok = randombuf(salt, SALTLEN);
	if(!ok)
		return "scrypt: failed to generate salt";
	return stanza(h, filekey, pass, salt, cost);
}

static const char *
stanza(Header *h, uchar filekey[16], char *pass, uchar *salt, uint cost)
{
	uchar b64salt[B64EBUFLEN(SALTLEN) + 1];
	uchar key[32];
	uchar body[32], b64body[B64EBUFLEN(32) + 1];
	const char *e;
	usize outlen;

	base64encode(salt, b64salt, SALTLEN, &outlen, 0);
	b64salt[sizeof(b64salt) - 1] = '\0';
	catlabel(salt);
	e = wrapkey(key, pass, salt, cost);
	if(e)
		return e;
	keyenc(key, filekey, body);
	base64encode(body, b64body, 32, &outlen, 0);
	b64body[sizeof(b64body) - 1] = '\0';
	e = hdrappend(h, "-> scrypt %s %d\n", b64salt, cost);
	if(e)
		return e;
	e = hdrappend(h, "%s\n", b64body);
	if(e)
		return e;
	return NULL;
}

static const char *
wrapkey(uchar key[32], char *pass, uchar *salt, uint factor)
{
	const char *e;

	e = scrypt((uchar *)pass, strlen(pass),
			salt, SALTLEN + sizeof(label) - 1,
			1<<factor, 8, 1, key, 32);
	if(e)
		return ewrap("scrypt", e);
	return NULL;
}

static void
catlabel(uchar *s)
{
	char salt[SALTLEN];

	memcpy(salt, s, SALTLEN);
	memcpy(s, label, sizeof(label) - 1);
	memcpy(s + sizeof(label) - 1, salt, SALTLEN);
}

int
scryptgetkey(uchar k[16], Scryptarg *arg, char *pass, const char **err)
{
	uchar salt[SALTLEN + sizeof(label) - 1];
	uchar wk[32];
	int ok;

	memcpy(salt, arg->salt, SALTLEN);
	catlabel(salt);
	*err = wrapkey(wk, pass, salt, arg->cost);
	if(*err)
		return 0;
	ok = keydec(wk, arg->body, k);
	if(!ok)
		return 0;
	return 1;
}
