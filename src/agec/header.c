#include "common.h"
#include "crypto.h"
#include "base64.h"
#include "util.h"
#include "header.h"

#define HDRINITLEN 128

static const uchar label[] = "header";

const char *
hdrinit(Header *h)
{
	h->data = malloc(HDRINITLEN);
	if(h->data == NULL)
		return eget();
	h->allocated = HDRINITLEN;
	h->len = 0;
	return NULL;
}

const char *
hdrappend(Header *h, char *fmt, ...)
{
	va_list l;
	char buf[256];
	uchar *ndata;
	usize nalloc;
	int ret;

	va_start(l, fmt);
	ret = vsnprintf(buf, sizeof(buf), fmt, l);
	va_end(l);
	if(ret < 0 || (usize)ret >= sizeof(buf))
		return "buffer overflow";
	if(h->len + ret >= h->allocated) {
		nalloc = h->len + ret + 1;
		ndata = realloc(h->data, nalloc);   /* keep h->data on failure */
		if(ndata == NULL)
			return eget();
		h->data = ndata;
		h->allocated = nalloc;
	}
	memcpy(h->data + h->len, buf, ret);
	h->len += ret;
	return NULL;
}

/* out length must be at least B64EBUFLEN(32) */
void
hdrmac(uchar *data, usize len, uchar filekey[16], char *out, usize *outlen)
{
	uchar md[32];

	mac(data, len, filekey, md);
	base64encode(md, (uchar *)out, sizeof(md), outlen, 0);
}

void
mac(uchar *data, usize len, uchar filekey[16], uchar out[32])
{
	uchar dk[32];

	hkdfsha256(filekey, 16, NULL, 0, label, sizeof(label) - 1, dk);
	hmacsha256(dk, sizeof(dk), data, len, out);
}
