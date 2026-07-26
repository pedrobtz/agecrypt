#include "common.h"
#include "util.h"

extern const char *argv0;
char ebuf[EBUFSIZE];

void
eset(const char *err)
{
	strncpy(ebuf, err, sizeof(ebuf) - 1);
	ebuf[sizeof(ebuf) - 1] = '\0';
}

const char *
ewrap(const char *outer, const char *inner)
{
	usize olen, ilen;

	olen = strlen(outer);
	ilen = strlen(inner);
	if(olen + 2 + ilen + 1 > sizeof(ebuf)) {
		if(olen + 2 + 1 > sizeof(ebuf)) {
			ilen = 0;
			olen = sizeof(ebuf) - 2 - 1;
		} else {
			ilen = sizeof(ebuf) - olen - 2 - 1;
		}
	}
	memmove(ebuf + olen + 2, inner, ilen);
	memcpy(ebuf, outer, olen);
	ebuf[olen] = ':';
	ebuf[olen + 1] = ' ';
	ebuf[olen + 2 + ilen] = '\0';
	return ebuf;
}

const char *
esys(const char *outer)
{
	return ewrap(outer, eget());
}

const char *
efmt(const char *fmt, ...)
{
	va_list l;

	va_start(l, fmt);
	(void)vsnprintf(ebuf, sizeof(ebuf), fmt, l);
	ebuf[sizeof(ebuf) - 1] = '\0';
	va_end(l);
	return ebuf;
}

void *
reallocarr(void *p, usize nmemb, usize size)
{
	usize n;

	n = nmemb * size;
	if(nmemb > 0 && n / nmemb != size) {
		eset("allocation length overflow");
		return NULL;
	}
	return realloc(p, n);
}

void
wipe(void *buf, usize len)
{
	volatile char *p;

	p = (char *)buf;
	while(len--)
		*p++ = 0;
}

const char *
xprogname(const char *arg0, const char *def)
{
	const char *s, *last;

	if(arg0 == NULL || *arg0 == '\0')
		return def;
	for(s = arg0, last = NULL; *s; s++) {
		if(*s == '/')
			last = s;
	}
	if(last == NULL)
		return arg0;
	if(last == s - 1)
		return def;
	return last + 1;
}
