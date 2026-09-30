#include "common.h"
#include "crypto.h"
#include "base64.h"
#include "util.h"
#include "io.h"
#include "header.h"

static const uchar label[] = "header";

void
hdrinit(Header *h, uchar filekey[16], Obuf *ob)
{
	uchar dk[32];

	hkdfsha256(filekey, 16, NULL, 0, label, sizeof(label) - 1, dk);
	hmacsha256init(&h->ctx, dk, sizeof(dk));
	h->ob = ob;
}

const char *
hdrappend(Header *h, char *fmt, ...)
{
	va_list l;
	char buf[256];
	ssize nw;
	int ret;
	
	va_start(l, fmt);
	ret = vsnprintf(buf, sizeof(buf), fmt, l);
	va_end(l);
	if(ret < 0 || (usize)ret >= sizeof(buf))
		return "buffer overflow";
	nw = bwrite(h->ob, buf, ret);
	if(nw == -1)
		return eget();
	hmacsha256update(&h->ctx, (uchar *)buf, ret);
	return NULL;
}

/* out length must be at least B64EBUFLEN(32) */
void
hdrfinish(Header *h, char mac[B64EBUFLEN(32)], usize *maclen)
{
	uchar md[32];

	hmacsha256final(&h->ctx, md);
	wipe(h, sizeof(*h));
	base64encode(md, (uchar *)mac, sizeof(md), maclen, 0);
}

void
mac(uchar *data, usize len, uchar filekey[16], uchar out[32])
{
	uchar dk[32];

	hkdfsha256(filekey, 16, NULL, 0, label, sizeof(label) - 1, dk);
	hmacsha256(dk, sizeof(dk), data, len, out);
}
