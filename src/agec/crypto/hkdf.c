#include "common.h"
#include "util.h"
#include "crypto.h"

/* Implemented only for 32 byte output */
void
hkdfsha256(const uchar *ikm, usize ikmlen, const uchar *salt, usize saltlen, const uchar *info, usize infolen, uchar out[32])
{
	Sha256ctx ctx;
	uchar prk[32], h[32], pad[64];
	static const uchar counter = 1;
	int i;

	hmacsha256(salt, saltlen, ikm, ikmlen, prk);    /* extract */
	memset(pad, 0x36, 64);
	for(i = 0; i < 32; i++)
		pad[i] ^= prk[i];
	sha256init(&ctx);
	sha256update(&ctx, pad, 64);
	sha256update(&ctx, info, infolen);
	sha256update(&ctx, &counter, 1);
	sha256final(&ctx, h);
	memset(pad, 0x5c, 64);
	for(i = 0; i < 32; i++)
		pad[i] ^= prk[i];
	sha256init(&ctx);
	sha256update(&ctx, pad, 64);
	sha256update(&ctx, h, 32);
	sha256final(&ctx, out);
	wipe(&ctx, sizeof(ctx));
	wipe(pad, sizeof(pad));
	wipe(prk, sizeof(prk));
	wipe(h, sizeof(h));
}
