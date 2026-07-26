#include "common.h"
#include "base64.h"
#include "header.h"
#include "scrypt.h"
#include "x25519.h"
#include "io.h"
#include "parse.h"
#include "util.h"

static ssize readc(Ibuf *b, char *c);
static int vchar(char c);
static int b64char(char c);
static const char *skipspace(Ibuf *b);
static const char *skipargline(Ibuf *b);
static const char *skipargbody(Ibuf *b);
static const char *skipstanza(Ibuf *b);
static const char *getarg(Ibuf *b, char *dest, int maxlen, int *len, int *read);
static const char *getscrypt(Ibuf *b, Stanza *s);
static const char *getx25519(Ibuf *b, Stanza *s);
static const char *x25519share(Ibuf *b, uchar out[32]);
static const char *x25519body(Ibuf *b, uchar out[32]);
static const char *scryptsalt(Ibuf *b, uchar out[16]);
static const char *scryptcost(Ibuf *b, int *cost);
static const char *scryptbody(Ibuf *b, uchar out[32]);
static int getb64seq(Ibuf *b, uchar *out, uchar *buf, usize rawlen, char term);

const char *
getversion(Ibuf *in)
{
	static const char *einval = "invalid version line";
	static const char h[] = "age-encryption.org/v1\n";
	char buf[sizeof(h) - 1];
	ssize nr;

	nr = bread(in, buf, sizeof(buf));
	if(nr == -1)
		return eget();
	if(nr != sizeof(buf))
		return einval;
	if(memcmp(buf, h, sizeof(buf)) != 0)
		return einval;
	return NULL;
}

static ssize
readc(Ibuf *b, char *c)
{
	return bread(b, c, 1);
}

static int
vchar(char c)
{
	return c >= 0x21 && c <= 0x7e;
}

static int
b64char(char c)
{
	/* not relying on isalnum(3) since it may be affected by locale */
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		|| (c >= '0' && c <= '9')
		|| c == '+' || c == '/';
}

/* Initial position: start of the optional arguments */
static const char *
skipargline(Ibuf *b)
{
	static const char *einval = "invalid stanza optional argument";
	ssize nr;
	int prevspace = 1;
	char c;

	for(;;) {
		nr = readc(b, &c);
		if(nr == -1)
			return eget();
		if(nr == 0)
			return einval;
		if(prevspace && (c == ' ' || c == '\n'))
			return einval;
		if(c == '\n')
			return NULL;
		if(c == ' ') {
			prevspace = 1;
		} else {
			if(!vchar(c))
				return einval;
			prevspace = 0;
		}
	}
}

static const char *
skipargbody(Ibuf *b)
{
	static const char *einval = "invalid stanza body";
	int linelen;
	ssize nr;
	char c;

	linelen = 0;
	for(;;) {
		nr = readc(b, &c);
		if(nr == -1)
			return eget();
		if(nr != 1)
			return einval;
		if(c == '\n') {
			if(linelen > 64)
				return einval;
			else if(linelen < 64)
				return NULL;
			linelen = 0;
			continue;
		}
		linelen++;
		if(linelen > 64 || !b64char(c))
			return einval;
	}
}

static const char *
skipstanza(Ibuf *b)
{
	static const char *einval = "invalid stanza";
	const char *e;
	ssize nr;
	char c;

	nr = readc(b, &c);
	if(nr == -1)
		return eget();
	if(nr != 1)
		return einval;
	if(c == ' ') {
		e = skipargline(b);
		if(e)
			return e;
	} else if(c != '\n') {
		return einval;
	}
	return skipargbody(b);
}

static const char *
getarg(Ibuf *b, char *dest, int maxlen, int *len, int *fullread)
{
	static const char *einval = "invalid stanza argument";
	ssize nr;
	char c;

	*len = 0;
	*fullread = 0;
	for(*len = 0; ; (*len)++, dest++) {
		nr = bpeek(b, &c);
		if(nr == -1)
			return eget();
		if(nr == 0)
			return einval;
		if(c == ' ' || c == '\n') {
			*fullread = 1;
			return NULL;
		}
		if(*len == maxlen)
			return NULL;
		if(!vchar(c))
			return einval;
		*dest = c;
		(void)readc(b, &c); /* not possible to fail after bpeek() */
	}
}

static const char *
skiparg(Ibuf *b)
{
	static const char *einval = "invalid stanza argument";
	ssize nr;
	char c;

	for(;;) {
		nr = bpeek(b, &c);
		if(nr == -1)
			return eget();
		if(nr == 0)
			return einval;
		if(c == ' ' || c == '\n')
			return NULL;
		if(!vchar(c))
			return einval;
		(void)readc(b, &c); /* not possible to fail after bpeek() */
	}
}

/* s is not touched if the end is reached. */
const char *
getstanza(Ibuf *in, Stanza *s, int *end)
{
	static const char *einval = "invalid stanza";
	static const char argscrypt[] = "scrypt";
	static const char argx25519[] = "X25519";
	char buf[sizeof(argscrypt) - 1];
	const char *e;
	ssize nr;
	int fullread, arglen;
	char c;

	nr = bread(in, buf, 3);
	if(nr == -1)
		return eget();
	if(nr != 3)
		return einval;
	*end = 0;
	if(memcmp(buf, "---", 3) == 0) {
		*end = 1;
		return NULL;
	} else if(memcmp(buf, "-> ", 3) != 0) {
		return einval;
	}
	e = getarg(in, buf, sizeof(buf), &arglen, &fullread);
	if(e)
		return e;
	s->type = UNKNOWN;
	if(!fullread) {
		e = skiparg(in);
		if(e)
			return e;
		goto unknown;
	}
	if(arglen != sizeof(buf))
		goto unknown;
	if(memcmp(buf, argscrypt, sizeof(argscrypt) - 1) == 0)
		s->type = SCRYPT;
	else if(memcmp(buf, argx25519, sizeof(argx25519) - 1) == 0)
		s->type = X25519;
	else
		goto unknown;
	nr = readc(in, &c);
	if(nr == -1)
		return eget();
	if(nr == 0 || c != ' ')
		return einval;
	if(s->type == SCRYPT)
		return getscrypt(in, s);
	if(s->type == X25519)
		return getx25519(in, s);
unknown:
	return skipstanza(in);
}

static const char *
getscrypt(Ibuf *b, Stanza *s)
{
	const char *e;

	s->type = SCRYPT;
	e = scryptsalt(b, s->arg.scrypt.salt);
	if(e)
		return e;
	e = scryptcost(b, &s->arg.scrypt.cost);
	if(e)
		return e;
	e = scryptbody(b, s->arg.scrypt.body);
	return e;
}

static const char *
getx25519(Ibuf *b, Stanza *s)
{
	const char *e;

	s->type = X25519;
	e = x25519share(b, s->arg.x25519.share);
	if(e)
		return e;
	return x25519body(b, s->arg.x25519.body);
}

static const char *
scryptsalt(Ibuf *b, uchar out[16])
{
	static const char *einval = "invalid scrypt salt";
	uchar b64buf[B64EBUFLEN(16)];
	int r;

	r = getb64seq(b, out, b64buf, 16, ' ');
	if(r == -1)
		return eget();
	else if(r == 0)
		return einval;
	else
		return NULL;
}

static const char *
scryptcost(Ibuf *b, int *cost)
{
	static const char *einval = "invalid scrypt work factor";
	char buf[6];
	ssize nr;
	uint i;
	char c;

	for(i = 0; i < sizeof(buf) - 1; i++) {
		nr = readc(b, &c);
		if(nr == -1)
			return eget();
		if(nr == 0)
			return einval;
		if(c == '\n')
			break;
		if(!(c >= '0' && c <= '9'))
			return einval;
		buf[i] = c;
	}
	if(i == 0 || i == sizeof(buf) - 1 || buf[0] == '0')
		return einval;
	buf[i] = '\0';
	*cost = atoi(buf);
	return NULL;
}

static const char *
scryptbody(Ibuf *b, uchar out[32])
{
	uchar b64buf[B64EBUFLEN(32)];
	int r;

	r = getb64seq(b, out, b64buf, 32, '\n');
	if(r == -1)
		return eget();
	else if(r == 0)
		return "invalid scrypt body";
	else
		return NULL;
}

static const char *
x25519share(Ibuf *b, uchar out[32])
{
	static const char *einval = "invalid X25519 share";
	uchar b64buf[B64EBUFLEN(32)];
	int r;

	r = getb64seq(b, out, b64buf, 32, '\n');
	if(r == -1)
		return eget();
	else if(r == 0)
		return einval;
	else
		return NULL;
}

static const char *
x25519body(Ibuf *b, uchar out[32])
{
	static const char *einval = "invalid X25519 body";
	uchar b64buf[B64EBUFLEN(32)];
	int r;

	r = getb64seq(b, out, b64buf, 32, '\n');
	if(r == -1)
		return eget();
	else if(r == 0)
		return einval;
	else
		return NULL;
}

/*
 * Read and decode a base64 sequence for a value of size rawlen,
 * terminated by term.
 * Size of buf must be at least B64EBUFLEN(rawsize).
 * Returns 1 for success, 0 for format error, -1 for IO failure.
 */
static int
getb64seq(Ibuf *b, uchar *out, uchar *buf, usize rawlen, char term)
{
	ssize nr;
	usize outlen;
	uint i;
	int ok;
	char c;

	for(i = 0; i < B64EBUFLEN(rawlen); i++) {
		nr = readc(b, &c);
		if(nr == -1)
			return -1;
		if(nr == 0)
			return 0;
		if(c == term)
			break;
		if(!b64char(c))
			return 0;
		buf[i] = c;
	}
	if(i == B64EBUFLEN(rawlen)) {
		nr = readc(b, &c);
		if(nr == -1)
			return -1;
		if(nr == 0 || c != term)
			return 0;
	}
	ok = base64decode(buf, out, i, &outlen, 0);
	if(!ok || outlen != rawlen)
		return 0;
	return 1;
}

static const char *
skipspace(Ibuf *b)
{
	ssize nr;
	char c;

	nr = readc(b, &c);
	if(nr == -1)
		return eget();
	if(nr == 0 || c != ' ')
		return "invalid header MAC";
	return NULL;
}

const char *
getmac(Ibuf *in, uchar mac[32])
{
	const char *e;
	uchar b64buf[B64EBUFLEN(32)];
	int r;

	e = skipspace(in);
	if(e)
		return e;
	r = getb64seq(in, mac, b64buf, 32, '\n');
	if(r == -1)
		return eget();
	else if(r == 0)
		return "invalid header MAC";
	return NULL;
}

const char *
getplnonce(Ibuf *in, uchar plnonce[16])
{
	ssize nr;

	nr = bread(in, plnonce, 16);
	if(nr == -1)
		return eget();
	if(nr < 16)
		return "payload nonce is too short";
	return NULL;
}
