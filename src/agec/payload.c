#include "common.h"
#include "base64.h"
#include "crypto.h"
#include "util.h"
#include "io.h"
#include "payload.h"

/* renamed from eof(): Windows <io.h> declares a CRT eof(int) that collides */
static int ateof(Ibuf *b);
static const char *incnonce(uchar nonce[12]);
static usize encchunk(Data in, uchar key[32], uchar nonce[12], uchar *out);
static usize decchunk(Data in, uchar key[32], uchar nonce[12], uchar *out);

static const char eemptychunk[] = "format error: final chunk is empty";
static const char enonceoverflow[] = "nonce overflow";

void
payloadkey(uchar filekey[16], uchar nonce[16], uchar plkey[32])
{
	static const uchar label[] = "payload";

	hkdfsha256(filekey, 16, nonce, 16, label, sizeof(label) - 1, plkey);
}

const char *
plencrypt(Ibuf *in, Obuf *out, uchar plkey[32])
{
	uchar inbuf[CHUNKLEN], outbuf[CHUNKLEN + TAGLEN];
	uchar nonce[12] = {0};
	Data ichunk;
	const char *e = NULL;
	usize outlen;
	ssize nr, nw;
	int last;

	ichunk.data = inbuf;
	for(last = 0; !last; e = incnonce(nonce)) {
		if(e)
			return e;
		nr = bread(in, inbuf, CHUNKLEN);
		if(nr == -1)
			return eget();
		last = ateof(in);
		if(last == -1)
			return eget();
		ichunk.len = nr;
		if(last)
			nonce[11] = 1;
		outlen = encchunk(ichunk, plkey, nonce, outbuf);
		nw = bwrite(out, outbuf, outlen);
		if(nw == -1)
			return eget();
	}
	return NULL;
}

static int
ateof(Ibuf *b)
{
	ssize nr;
	char c;

	if(b->eof)
		return 1;
	nr = bpeek(b, &c);
	if(nr == -1)
		return -1;
	else if(nr == 0)
		return 1;
	else
		return 0;
}

static const char *
incnonce(uchar nonce[12])
{
	int i;

	for(i = 10; i > 0; i--) {
		nonce[i]++;
		if(nonce[i] != 0)
			break;
		if(i == 0)
			return "payload is too long; chunk counter wrapped";
	}
	return NULL;
}

static usize
encchunk(Data in, uchar key[32], uchar nonce[12], uchar *out)
{
	Chacha20poly1305ctx ctx;

	chacha20poly1305init(&ctx, key, nonce);
	chacha20poly1305write(&ctx, out, NULL, 0, in.data, in.len);
	wipe(&ctx, sizeof(ctx));
	return in.len + TAGLEN;
}

const char *
pldecrypt(Ibuf *in, Obuf *out, uchar plkey[32])
{
	uchar outbuf[CHUNKLEN + TAGLEN], inbuf[CHUNKLEN + TAGLEN];
	uchar nonce[12] = {0};
	Data ichunk;
	const char *e = NULL;
	usize outlen;
	ssize nr, nw;
	int last, i;

	ichunk.data = inbuf;
	for(last = 0, i = 0; !last; e = incnonce(nonce), i++) {
		if(e)
			return e;
		nr = bread(in, inbuf, sizeof(inbuf));
		if(nr == -1)
			return eget();
		last = ateof(in);
		if(last == -1)
			return eget();
		if(last && i > 0 && nr == TAGLEN)
			return eemptychunk;
		ichunk.len = nr;
		if(last)
			nonce[11] = 1;
		outlen = decchunk(ichunk, plkey, nonce, outbuf);
		if(outlen == ~(usize)0)
			return eget();
		nw = bwrite(out, outbuf, outlen);
		if(nw == -1)
			return eget();
	}
	return NULL;
}

static usize
decchunk(Data in, uchar key[32], uchar nonce[12], uchar *out)
{
	Chacha20poly1305ctx ctx;
	int fail;

	chacha20poly1305init(&ctx, key, nonce);
	fail = chacha20poly1305read(&ctx, out, NULL, 0, in.data, in.len);
	if(fail) {
		eset("failed to decrypt and authenticate payload");
		return ~(usize)0;
	}
	wipe(&ctx, sizeof(ctx));
	return in.len - TAGLEN;
}

const char *
plinit(Ebuf *b, Ibuf *ib, uchar plkey[32])
{
	b->in = ib;
	memcpy(b->key, plkey, 32);
	memset(b->nonce, 0, sizeof(b->nonce));
	b->cur = b->size = b->nchunk = 0;
	return NULL;
}

void
plfree(Ebuf *b)
{
	wipe(b, sizeof(*b));
}

ssize
plread(Ebuf *b, void *buf, usize nbytes)
{
	Data ichunk;
	const char *e;
	usize orig = nbytes, c, rest;
	ssize nr;
	int last;

	ichunk.data = b->ibuf;
	while(nbytes > 0) {
		if(b->cur == b->size) {
			if(b->nonce[11] == 1)
				return 0;
			b->cur = b->size = 0;
		}
		if(b->size == 0) {
			last = ateof(b->in);
			if(last == -1)
				return -1;
			if(last)
				b->nonce[11] = 1;
			nr = bread(b->in, b->ibuf, sizeof(b->ibuf));
			if(last && b->nchunk > 0 && nr == TAGLEN) {
				eset(eemptychunk);
				return -1;
			}
			if(nr == -1)
				return -1;
			if(nr == 0)
				return 0;
			b->nchunk++;
			ichunk.len = nr;
			b->size = decchunk(ichunk, b->key, b->nonce, b->obuf);
			if(b->size == ~(usize)0)
				return -1;
			e = incnonce(b->nonce);
			if(e) {
				eset(enonceoverflow);
				return -1;
			}
		}
		rest = b->size - b->cur;
		c = (rest > nbytes) ? nbytes : rest;
		memcpy(buf, b->obuf + b->cur, c);
		buf = (uchar *)buf + c;
		b->cur += c;
		nbytes -= c;
	}
	return orig - nbytes;
}

ssize
plpeek(Ebuf *b, char *c)
{
	Data ichunk;
	const char *e;
	int last;
	ssize nr;

	ichunk.data = b->ibuf;
	if(b->cur < b->size) {
		*c = b->obuf[b->cur];
		return 1;
	}
	b->cur = b->size = 0;
	nr = bread(b->in, b->ibuf, sizeof(b->ibuf));
	if(nr == -1)
		return -1;
	if(nr == 0)
		return 0;
	last = ateof(b->in);
	if(last == -1)
		return -1;
	if(last)
		b->nonce[11] = 1;
	ichunk.len = nr;
	b->size = decchunk(ichunk, b->key, b->nonce, b->obuf);
	if(b->size == 0)
		return -1;
	e = incnonce(b->nonce);
	if(e) {
		eset(enonceoverflow);
		return -1;
	}
	*c = b->obuf[0];
	return 1;
}
