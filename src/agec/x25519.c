#include "common.h"
#include "base64.h"
#include "bech32.h"
#include "header.h"
#include "keyenc.h"
#include "util.h"
#include "crypto.h"
#include "x25519.h"

#define HDRINITLEN  128
#define BECHPUBLEN  62
#define BECHPRIVLEN 74
#define TAGLEN      16      /* poly1305 authentication tag */

static const char *ezeroresult = "curve25519 low order point";

static void wrap(uchar out[32], uchar share[32], uchar secret[32], uchar pubkey[32]);
static const char *body(uchar share[32], uchar esecret[32], uchar pubkey[32], uchar filekey[16], uchar out[32]);

const char *
x25519stanza(Header *h, uchar filekey[16], uchar pubkey[32])
{
	uchar esecret[32], share[32];
	uchar b64share[B64EBUFLEN(sizeof(share)) + 1];
	uchar b[32], b64body[B64EBUFLEN(32) + 1];
	const char *e;
	usize outlen;
	int ok;

	ok = randombuf(esecret, sizeof(esecret));
	if(!ok)
		return "failed to generate ephemeral secret";
	ok = x25519(share, esecret, curve25519basepoint);
	if(!ok) {
		e = ezeroresult;
		goto out;
	}
	base64encode(share, b64share, sizeof(share), &outlen, 0);
	b64share[sizeof(b64share) - 1] = '\0';
	e = hdrappend(h, "-> X25519 %s\n", b64share);
	if(e)
		goto out;
	e = body(share, esecret, pubkey, filekey, b);
	if(e)
		goto out;
	base64encode(b, b64body, 32, &outlen, 0);
	b64body[sizeof(b64body) - 1] = '\0';
	e = hdrappend(h, "%s\n", b64body);
out:
	wipe(esecret, sizeof(esecret));
	return e;
}

static const char *
body(uchar share[32], uchar esecret[32], uchar pubkey[32], uchar filekey[16], uchar out[32])
{
	uchar secret[32], wrapkey[32];
	int ok;

	ok = x25519(secret, esecret, pubkey);
	if(!ok) {
		wipe(secret, sizeof(secret));
		return ezeroresult;
	}
	wrap(wrapkey, share, secret, pubkey);
	keyenc(wrapkey, filekey, out);
	wipe(secret, sizeof(secret));
	return NULL;
}

static void
wrap(uchar out[32], uchar share[32], uchar secret[32], uchar pubkey[32])
{
	static const uchar info[] = "age-encryption.org/v1/X25519";
	uchar salt[64];

	memcpy(salt, share, 32);
	memcpy(salt + 32, pubkey, 32);
	hkdfsha256(secret, 32, salt, sizeof(salt),
			info, sizeof(info) - 1, out);
}

int
x25519pubkey(char *bech, uchar pubkey[32])
{
	static const char goodprefix[] = "age1";
	uchar data[BECHPUBLEN - 8];
	usize datalen, hrplen;
	int ok;

	if(strlen(bech) != BECHPUBLEN)
		return 0;
	if(memcmp(bech, goodprefix, sizeof(goodprefix) - 1) != 0)
		return 0;
	ok = bech32decode(bech, data, &datalen, &hrplen);
	if(!ok)
		return 0;
	if(datalen != 32)
		return 0;
	memcpy(pubkey, data, 32);
	return 1;
}

int
x25519privkey(char bech[74+1], uchar privkey[32])
{
	static const char goodprefix[] = "AGE-SECRET-KEY-1";
	uchar data[BECHPRIVLEN - 8];
	usize datalen, hrplen;
	int ok;

	bech[74] = '\0';
	if(memcmp(bech, goodprefix, sizeof(goodprefix) - 1) != 0)
		return 0;
	ok = bech32decode(bech, data, &datalen, &hrplen);
	if(!ok)
		return 0;
	if(datalen != 32)
		return 0;
	memcpy(privkey, data, 32);
	return 1;
}

int
x25519getkey(uchar k[16], X25519arg *arg, uchar privkey[32], const char **err)
{
	uchar secret[32], pubkey[32], wrapkey[32];
	int ok;

	ok = x25519(secret, privkey, arg->share);
	if(!ok) {
		*err = ezeroresult;
		return 0;
	}
	ok = x25519pub(pubkey, privkey);
	if(!ok) {
		*err = ezeroresult;
		return 0;
	}
	wrap(wrapkey, arg->share, secret, pubkey);
	return keydec(wrapkey, arg->body, k);
}
