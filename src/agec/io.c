#include "common.h"
#include "base64.h"
#include "util.h"
#include "io.h"
#include "memio.h"

#define RECINITLEN 512
#define UNCHECKED  2

const char armorfirst[36] = "-----BEGIN AGE ENCRYPTED FILE-----\n";
const char armorlast[34]  = "-----END AGE ENCRYPTED FILE-----\n";
typedef char armorfirst_must_fit_iobuf[(sizeof(armorfirst) - 1 < IOBUFSIZE) ? 1 : -1];

static ssize awrite(Obuf *b, void *buf, usize nbytes);
static ssize aflush(Obuf *b);
static void recappend(Ibuf *b, void *buf, usize len);
static ssize readall(int fd, void *buf, usize nbytes, int *eof);
static int isarmor(Ibuf *b);
static int endcheck(uchar *buf, usize len, int *endpos);
static int endskip(int fd, int endpos);
static ssize aread(Ibuf *b, void *buf, usize nbytes);

ssize
bwrite(Obuf *b, void *buf, usize nbytes)
{
	usize rest, c;
	ssize ret;

	if(b->isarmor)
		return awrite(b, buf, nbytes);
	if(nbytes > IOBUFSIZE) {
		ret = bflush(b);
		if(ret == -1)
			return -1;
		return writeall(b->fd, buf, nbytes);
	}
	rest = IOBUFSIZE - b->cur;
	c = (rest > nbytes) ? nbytes : rest;
	memcpy(b->buf.buf + b->cur, buf, c);
	if(rest > nbytes) {
		b->cur += nbytes;
		return 0;
	} else {
		ret = writeall(b->fd, b->buf.buf, b->cur);
		if(ret == -1)
			return -1;
		memcpy(b->buf.buf, (uchar *)buf + rest, nbytes - rest);
		b->cur = nbytes - rest;
		return ret;
	}
}

static ssize
awrite(Obuf *b, void *buf, usize nbytes)
{
	usize rest, c;
	ssize r;

	while(nbytes > 0) {
		rest = sizeof(b->buf.abuf) - b->cur;
		c = (rest > nbytes) ? nbytes : rest; 
		memcpy(b->buf.abuf + b->cur, buf, c);
		buf = (char *)buf + c;
		b->cur += c;
		nbytes -= c;
		if(b->cur == sizeof(b->buf.abuf)) {
			r = aflush(b);
			if(r == -1)
				return -1;
		}
	}
	return 1;
}

static ssize
aflush(Obuf *b)
{
	uchar buf[IOABUFSIZE];
	usize outlen;
	ssize r;

	if(b->cur == 0)
		return 0;
	base64encode(b->buf.abuf, buf, b->cur, &outlen, 1);
	r = writeall(b->fd, buf, outlen);
	b->cur = 0;
	return r;
}

ssize
bflush(Obuf *b)
{
	ssize r;

	if(b->isarmor)
		return aflush(b);
	if(b->cur == 0)
		return 0;
	r = writeall(b->fd, b->buf.buf, b->cur);
	b->cur = 0;
	return r;
}

static ssize
readall(int fd, void *buf, usize nbytes, int *eof)
{
	ssize nr, total = 0;

	while(nbytes > 0) {
		nr = ageread(fd, buf, nbytes);
		if(nr < 0)
			return nr;
		if(nr == 0) {
			*eof = 1;
			return total;
		}
		nbytes -= nr;
		total += nr;
		buf = (char *)buf + nr;
	}
	return total;
}

static int
isarmor(Ibuf *b)
{
	ssize nr;

	nr = readall(b->fd, b->buf, sizeof(armorfirst) - 1, &b->eof);
	if(nr == -1)
		return -1;
	if(nr == 0)
		b->eof = 1;
	b->size = nr;
	if((usize)nr < sizeof(armorfirst) - 1)
		return 0;
	if(memcmp(armorfirst, b->buf, sizeof(armorfirst) - 1) == 0) {
		b->size = 0;
		return 1;
	} else {
		return 0;
	}
}

void
ibinit(Ibuf *b, int fd)
{
	b->size = b->cur = 0;
	b->asize = b->acur = b->aendpos = 0;
	b->eof = 0;
	b->fd = fd;
	b->recording = 1;
	b->recfail = NULL;
	b->rec.len = b->rec.capacity = 0;
	b->isarmor = UNCHECKED;
}

void
ibfree(Ibuf *b)
{
	if(b->rec.capacity > 0) {
		wipe(b->rec.buf, b->rec.capacity);
		free(b->rec.buf);
	}
	wipe(b, sizeof(*b));
}

ssize
bread(Ibuf *b, void *buf, usize nbytes)
{
	usize c, rest;
	usize orig = nbytes;
	ssize nr;

	if(b->isarmor == UNCHECKED) {
		b->isarmor = isarmor(b);
		if(b->isarmor == -1)
			return -1;
	}
	/*
	 * Divergence from upstream agec: only report EOF here once the bytes
	 * buffered by the armor probe (isarmor) have been consumed. Upstream
	 * returns 0 whenever b->eof is set, which drops the whole input when
	 * it is shorter than the 35-byte probe (e.g. encrypting "hello").
	 */
	if(b->eof && b->cur == b->size)
		return 0;
	while(nbytes > 0) {
		if(b->cur == b->size) {
			if(b->recording && b->size > 0)
				recappend(b, b->buf, b->size);
			b->cur = b->size = 0;
		}
		if(b->size == 0) {
			if(b->isarmor)
				nr = aread(b, b->buf, IOBUFSIZE);
			else
				nr = ageread(b->fd, b->buf, IOBUFSIZE);
			if(nr == -1)
				return -1;
			if(nr == -2) {
				eset("armor format error");
				return -1;
			}
			if(nr == 0) {
				b->eof = 1;
				return orig - nbytes;
			}
			b->size = nr;
		}
		rest = b->size - b->cur;
		c = (rest > nbytes) ? nbytes : rest;
		memcpy(buf, b->buf + b->cur, c);
		buf = (uchar *)buf + c;
		b->cur += c;
		nbytes -= c;
	}
	return orig - nbytes;
}

/*
 * Checks for the PEM ending line.
 * Return value is:
 *   1 if the ending line fully resides in the buf
 *   0 if there is no ending line in the buf, or it's partial
 *  -1 for the format error
 * endpos must point to the size of the ending line part that
 * has already been read (zero if has not). The value is
 * updated if the ending line is partial.
 */
static int
endcheck(uchar *buf, usize len, int *endpos)
{
	usize start;
	const char *p, *q;

	if(len - *endpos < sizeof(armorlast) - 1)
		return -1;
	start = len - *endpos - (sizeof(armorlast) - 1);
	p = (char *)buf + start;
	q = armorlast + *endpos;

	if(*p != *q && *endpos == 0) {
		while(p < (char *)buf + len) {
			if(*p == '-')
				break;
			p++;
		}
		return 0;
	}
	while(p <= (char *)buf + len) {
		if(q == armorlast + (sizeof(armorlast) - 1)) /* end */
			return (p == (char *)buf + len) ? 1 : -1;
		if(*p != *q)
			return -1;
		p++, q++;
		(*endpos)++;
	}
	return 0;
}

static int
endskip(int fd, int endpos)
{
	uchar buf[sizeof(armorlast)];
	ssize nr, nr2;
	int eof;

	nr = readall(fd, buf, sizeof(armorlast) - endpos, &eof);
	if(nr == -1)
		return -1;
	if(nr < (ssize)(sizeof(armorlast) - 1) - endpos)
		return -2;
	if(memcmp(buf, armorlast + endpos, (sizeof(armorlast)-1) - endpos) != 0)
		return -2;
	nr2 = ageread(fd, buf, 1);
	if(nr2 == -1)
		return -1;
	if(nr2 > 0)
		return -2;
	return nr;
}

static ssize
aread(Ibuf *b, void *buf, usize nbytes)
{
	uchar raw[IOABUFREADSIZE];
	usize rest, c, outlen, orig = nbytes;
	ssize nr;
	int ok, end, eof;

	while(nbytes > 0) {
		if(b->acur == b->asize)
			b->acur = b->asize = 0;
		if(b->asize == 0) {
			nr = readall(b->fd, raw, sizeof(raw), &eof);
			if(nr == -1)
				return -1;
			if(nr == 0) {
				if(b->aendpos == 0)
					return -2;
				return orig - nbytes;
			}
			end = endcheck(raw, nr, &b->aendpos);
			if(end == -1)
				return -2;
			ok = base64decode(raw, b->abuf, nr - b->aendpos,
					&outlen, 1);
			if(!ok)
				return -2;
			b->asize = outlen;
			if(end == 0 && b->aendpos > 0) {   /* partial */
				endskip(b->fd, b->aendpos);
			} else if(end == 1) {   /* full */
				/* it must be the last block */
				nr = ageread(b->fd, raw, 1);
				if(nr == -1)
					return -1;
				if(nr != 0)
					return -2;
			}
		}
		rest = b->asize - b->acur;
		c = (rest > nbytes) ? nbytes : rest;
		memcpy(buf, b->abuf + b->acur, c);
		b->acur += c;
		buf = (uchar *)buf + c;
		nbytes -= c;
	}
	return orig - nbytes;
}

ssize
bpeek(Ibuf *b, char *c)
{
	ssize nr;

	if(b->isarmor == UNCHECKED) {
		b->isarmor = isarmor(b);
		if(b->isarmor == -1)
			return -1;
	}
	if(b->eof && b->cur == b->size)     /* see the note in bread() */
		return 0;
	if(b->cur < b->size) {
		*c = b->buf[b->cur];
		return 1;
	}
	if(b->recording && b->size > 0)
		recappend(b, b->buf, b->size);
	b->cur = b->size = 0;
	if(b->isarmor)
		nr = aread(b, b->buf, IOBUFSIZE);
	else
		nr = ageread(b->fd, b->buf, IOBUFSIZE);
	if(nr == -1)
		return -1;
	if(nr == 0) {
		b->eof = 1;
		return 0;
	}
	b->size = nr;
	*c = b->buf[0];
	return 1;
}

static void
recappend(Ibuf *b, void *buf, usize len)
{
	usize cap, ncap;
	uchar *nbuf;

	if(b->recfail)
		return;
	if(len > 0 && b->rec.capacity == 0) {
		b->rec.buf = malloc(RECINITLEN);
		if(b->rec.buf == NULL) {
			b->recfail = eget();
			return;
		}
		b->rec.capacity = RECINITLEN;
	}
	if(b->rec.len + len > b->rec.capacity) {
		cap = ncap = b->rec.capacity;
		while(b->rec.len + len > ncap) {
			ncap *= 2;
			if(ncap < cap) {
				b->recfail = "allocation length overflow";
				return;
			}
			cap = ncap;
		}
		nbuf = realloc(b->rec.buf, ncap);   /* keep b->rec.buf on failure */
		if(nbuf == NULL) {
			b->recfail = eget();
			return;
		}
		b->rec.buf = nbuf;
		b->rec.capacity = ncap;
	}
	memcpy(b->rec.buf + b->rec.len, buf, len);
	b->rec.len += len;
}

uchar *
recstop(Ibuf *b, usize *len)
{
	b->recording = 0;
	if(b->recfail) {
		eset(b->recfail);
		return NULL;
	}
	if(b->rec.capacity == 0) {
		*len = b->cur;
		return b->buf;
	} else {
		recappend(b, b->buf, b->cur);
		*len = b->rec.len;
		return b->rec.buf;
	}
}

ssize
writeall(int fd, const void *buf, usize nbytes)
{
	usize off;
	ssize nw;

	for(off = 0; off < nbytes; off += nw) {
		nw = agewrite(fd, (char *)buf + off, nbytes - off);
		if(nw <= 0)
			return -1;
	}
	return nbytes;
}
