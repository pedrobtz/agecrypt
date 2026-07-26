#include "common.h"
#include "util.h"
#include "crypto.h"

void
hmacsha256(const uchar *k, usize klen, const uchar *in, usize inlen, uchar out[32])
{
	Hmacsha256ctx ctx;

	hmacsha256init(&ctx, k, klen);
	hmacsha256update(&ctx, in, inlen);
	hmacsha256final(&ctx, out);
	wipe(&ctx, sizeof(ctx));
}

void
hmacsha256init(Hmacsha256ctx *ctx, const uchar *k, usize klen)
{
	uchar pad[64], kh[32];
	usize i;

	if(klen > 64) {
		sha256init(&ctx->inner);
		sha256update(&ctx->inner, k, klen);
		sha256final(&ctx->inner, kh);
		k = kh;
		klen = 32;
	}
	sha256init(&ctx->inner);
	sha256init(&ctx->outer);
	memset(pad, 0x36, 64);
	for(i = 0; i < klen; i++)
		pad[i] ^= k[i];
	sha256update(&ctx->inner, pad, 64);
	memset(pad, 0x5c, 64);
	for(i = 0; i < klen; i++)
		pad[i] ^= k[i];
	sha256update(&ctx->outer, pad, 64);
	wipe(pad, sizeof(pad));
	wipe(kh, sizeof(kh));
}

void
hmacsha256update(Hmacsha256ctx *ctx, const uchar *in, usize inlen)
{
	sha256update(&ctx->inner, in, inlen);
}

void
hmacsha256final(Hmacsha256ctx *ctx, uchar out[32])
{
	uchar h[32];

	sha256final(&ctx->inner, h);
	sha256update(&ctx->outer, h, 32);
	sha256final(&ctx->outer, out);
	wipe(h, sizeof(h));
}
