/* Public domain. Extracted from monocypher-4.0.2. */
#include "common.h"
#include "util.h"
#include "crypto.h"

#define COPY(dst, src, size)       memcpy(dst, src, size * sizeof((*dst)))
#define ZERO(buf, size)            memset(buf, 0, size * sizeof((*buf)))
#define WIPE_CTX(ctx)              wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)        wipe(buffer, sizeof(buffer))
#define MIN(a, b)                  ((a) <= (b) ? (a) : (b))

typedef uint8  u8;
typedef uint32 u32;
typedef uint64 u64;

static const u8 *chacha20_constant = (const u8*)"expand 32-byte k"; /*16 bytes*/
static const u8 zero[128] = {0};

/* Incremental interface */
typedef struct {
	/*
	 * Do not rely on the size or contents of this type,
	 * for they may change without notice.
	 */
	uchar    c[16];  /* chunk of the message */
	usize    c_idx;  /* How many bytes are there in the chunk. */
	uint32   r  [4]; /* constant multiplier (from the secret key) */
	/* random number added at the end (from the secret key) */
	uint32   pad[4];
	uint32   h  [5]; /* accumulated hash */
} poly1305_ctx;

/*
 * returns the smallest positive integer y such that
 * (x + y) % pow_2  == 0
 * Basically, y is the "gap" missing to align x.
 * Only works when pow_2 is a power of 2.
 * Note: we use ~x+1 instead of -x to avoid compiler warnings
 */
static usize
gap(usize x, usize pow_2)
{
	return (~x + 1) & (pow_2 - 1);
}

static u32
load32_le(const u8 s[4])
{
	return
		((u32)s[0] <<  0) |
		((u32)s[1] <<  8) |
		((u32)s[2] << 16) |
		((u32)s[3] << 24);
}

static u64
load64_le(const u8 s[8])
{
	return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

static void
store32_le(u8 out[4], u32 in)
{
	out[0] =  in        & 0xff;
	out[1] = (in >>  8) & 0xff;
	out[2] = (in >> 16) & 0xff;
	out[3] = (in >> 24) & 0xff;
}

static void
load32_le_buf (u32 *dst, const u8 *src, usize size) {
	usize i;

	for (i = 0; i < size; i++)
		dst[i] = load32_le(src + i*4);
}

static void
store64_le(u8 out[8], u64 in)
{
	store32_le(out    , (u32)in );
	store32_le(out + 4, in >> 32);
}

static u64
x16(const u8 a[16], const u8 b[16])
{
	return (load64_le(a + 0) ^ load64_le(b + 0))
		|  (load64_le(a + 8) ^ load64_le(b + 8));
}

static u32
rotl32(u32 x, u32 n) { return (x << n) ^ (x >> (32 - n)); }

static int
neq0(u64 diff)
{
	/* constant time comparison to zero */
	/* return diff != 0 ? -1 : 0 */
	u64 half = (diff >> 32) | ((u32)diff);
	return (1 & ((half - 1) >> 32)) - 1;
}

int
verify16(const u8 a[16], const u8 b[16]){ return neq0(x16(a, b)); }

#define QUARTERROUND(a, b, c, d)        \
	a += b;  d = rotl32(d ^ a, 16); \
	c += d;  b = rotl32(b ^ c, 12); \
	a += b;  d = rotl32(d ^ a,  8); \
	c += d;  b = rotl32(b ^ c,  7)

static void
chacha20_rounds(u32 out[16], const u32 in[16])
{
	int i;

	/* The temporary variables make Chacha20 10% faster. */
	u32 t0  = in[ 0]; u32 t1  = in[ 1]; u32 t2  = in[ 2]; u32 t3  = in[ 3];
	u32 t4  = in[ 4]; u32 t5  = in[ 5]; u32 t6  = in[ 6]; u32 t7  = in[ 7];
	u32 t8  = in[ 8]; u32 t9  = in[ 9]; u32 t10 = in[10]; u32 t11 = in[11];
	u32 t12 = in[12]; u32 t13 = in[13]; u32 t14 = in[14]; u32 t15 = in[15];

	for (i = 0; i < 10; i++) { /* 20 rounds, 2 rounds per loop. */
		QUARTERROUND(t0, t4, t8 , t12); /* column 0 */
		QUARTERROUND(t1, t5, t9 , t13); /* column 1 */
		QUARTERROUND(t2, t6, t10, t14); /* column 2 */
		QUARTERROUND(t3, t7, t11, t15); /* column 3 */
		QUARTERROUND(t0, t5, t10, t15); /* diagonal 0 */
		QUARTERROUND(t1, t6, t11, t12); /* diagonal 1 */
		QUARTERROUND(t2, t7, t8 , t13); /* diagonal 2 */
		QUARTERROUND(t3, t4, t9 , t14); /* diagonal 3 */
	}
	out[ 0] = t0;   out[ 1] = t1;   out[ 2] = t2;   out[ 3] = t3;
	out[ 4] = t4;   out[ 5] = t5;   out[ 6] = t6;   out[ 7] = t7;
	out[ 8] = t8;   out[ 9] = t9;   out[10] = t10;  out[11] = t11;
	out[12] = t12;  out[13] = t13;  out[14] = t14;  out[15] = t15;
}


static u64
chacha20_djb(u8 *cipher_text, const u8 *plain_text, usize text_size, const u8 key[32], const u8 nonce[8], u64 ctr)
{
	u32 input[16];
	usize i, j;

	/* Whole blocks */
	u32    pool[16];
	usize  nb_blocks = text_size >> 6;

	load32_le_buf(input     , chacha20_constant, 4);
	load32_le_buf(input +  4, key              , 8);
	load32_le_buf(input + 14, nonce            , 2);
	input[12] = (u32) ctr;
	input[13] = (u32)(ctr >> 32);
	for (i = 0; i < nb_blocks; i++) {
		chacha20_rounds(pool, input);
		if (plain_text != 0) {
			for (j = 0; j < 16; j++) {
				u32 p = pool[j] + input[j];
				store32_le(cipher_text,
						p ^ load32_le(plain_text));
				cipher_text += 4;
				plain_text  += 4;
			}
		} else {
			for (j = 0; j < 16; j++) {
				u32 p = pool[j] + input[j];
				store32_le(cipher_text, p);
				cipher_text += 4;
			}
		}
		input[12]++;
		if (input[12] == 0) {
			input[13]++;
		}
	}
	text_size &= 63;

	/* Last (incomplete) block */
	if (text_size > 0) {
		u8 tmp[64];
		if (plain_text == 0) {
			plain_text = zero;
		}
		chacha20_rounds(pool, input);
		for (i = 0; i < 16; i++) {
			store32_le(tmp + i*4, pool[i] + input[i]);
		}
		for (i = 0; i < text_size; i++) {
			cipher_text[i] = tmp[i] ^ plain_text[i];
		}
		WIPE_BUFFER(tmp);
	}
	ctr = input[12] + ((u64)input[13] << 32) + (text_size > 0);

	WIPE_BUFFER(pool);
	WIPE_BUFFER(input);
	return ctr;
}

/*
 * h = (h + c) * r
 * preconditions:
 *   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
 *   ctx->r <=   0ffffffc_0ffffffc_0ffffffc_0fffffff
 *   end    <= 1
 * Postcondition:
 *   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
 */
static void
poly_blocks(poly1305_ctx *ctx, const u8 *in, usize nb_blocks, uint end)
{
	u64 s0, s1, s2, s3, x0, x1, x2, x3, u0, u1, u2, u3;
	u32 s4, x4, u4, u5;
	/* Local all the things! */
	const u32 r0 = ctx->r[0];
	const u32 r1 = ctx->r[1];
	const u32 r2 = ctx->r[2];
	const u32 r3 = ctx->r[3];
	const u32 rr0 = (r0 >> 2) * 5;  /* lose 2 bits... */
	const u32 rr1 = (r1 >> 2) + r1; /* rr1 == (r1 >> 2) * 5 */
	const u32 rr2 = (r2 >> 2) + r2; /* rr1 == (r2 >> 2) * 5 */
	const u32 rr3 = (r3 >> 2) + r3; /* rr1 == (r3 >> 2) * 5 */
	const u32 rr4 = r0 & 3;         /* ...recover 2 bits */
	u32 h0 = ctx->h[0];
	u32 h1 = ctx->h[1];
	u32 h2 = ctx->h[2];
	u32 h3 = ctx->h[3];
	u32 h4 = ctx->h[4];
	usize i;

	for (i = 0; i < nb_blocks; i++) {
		/* h + c, without carry propagation */
		s0 = (u64)h0 + load32_le(in);  in += 4;
		s1 = (u64)h1 + load32_le(in);  in += 4;
		s2 = (u64)h2 + load32_le(in);  in += 4;
		s3 = (u64)h3 + load32_le(in);  in += 4;
		s4 =      h4 + end;

		/* (h + c) * r, without carry propagation */
		/*
		 * Expressions are splitted as a workaround for
		 * the Plan 9's 386 compiler.
		 */
		x0 = s0*r0 + s1*rr3; x0 += s2*rr2 + s3*rr1; x0 += s4*rr0;
		x1 = s0*r1 + s1*r0;  x1 += s2*rr3 + s3*rr2; x1 += s4*rr1;
		x2 = s0*r2 + s1*r1;  x2 += s2*r0  + s3*rr3; x2 += s4*rr2;
		x3 = s0*r3 + s1*r2;  x3 += s2*r1  + s3*r0 ; x3 += s4*rr3;
		x4 =                                              s4*rr4;
		
		/* partial reduction modulo 2^130 - 5 */
		u5 = x4 + (x3 >> 32); /* u5 <= 7ffffff5 */
		u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
		u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
		u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
		u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
		u4 = (u3 >> 32)     + (u5 & 3); /* u4 <= 4 */

		/* Update the hash */
		h0 = u0 & 0xffffffff;
		h1 = u1 & 0xffffffff;
		h2 = u2 & 0xffffffff;
		h3 = u3 & 0xffffffff;
		h4 = u4;
	}
	ctx->h[0] = h0;
	ctx->h[1] = h1;
	ctx->h[2] = h2;
	ctx->h[3] = h3;
	ctx->h[4] = h4;
}

static void
poly1305_init(poly1305_ctx *ctx, const u8 key[32])
{
	int i;

	ZERO(ctx->h, 5); /* Initial hash is zero */
	ctx->c_idx = 0;
	/* load r and pad (r has some of its bits cleared) */
	load32_le_buf(ctx->r  , key   , 4);
	load32_le_buf(ctx->pad, key+16, 4);
	for (i = 0; i < 1; i++)
		ctx->r[i] &= 0x0fffffff;
	for (i = 1; i < 4; i++)
		ctx->r[i] &= 0x0ffffffc;
}

static void
poly1305_update(poly1305_ctx *ctx, const u8 *message, usize message_size)
{
	usize i, aligned, nb_blocks;

	/* Avoid undefined NULL pointer increments with empty messages */
	if (message_size == 0) {
		return;
	}

	/* Align ourselves with block boundaries */
	aligned = MIN(gap(ctx->c_idx, 16), message_size);
	for (i = 0; i < aligned; i++) {
		ctx->c[ctx->c_idx] = *message;
		ctx->c_idx++;
		message++;
		message_size--;
	}

	/* If block is complete, process it */
	if (ctx->c_idx == 16) {
		poly_blocks(ctx, ctx->c, 1, 1);
		ctx->c_idx = 0;
	}

	/* Process the message block by block */
	nb_blocks = message_size >> 4;
	poly_blocks(ctx, message, nb_blocks, 1);
	message      += nb_blocks << 4;
	message_size &= 15;

	/* remaining bytes (we never complete a block here) */
	for (i = 0; i < message_size; i++) {
		ctx->c[ctx->c_idx] = message[i];
		ctx->c_idx++;
	}
}

static void
poly1305_final(poly1305_ctx *ctx, u8 mac[16])
{
	u64 c;
	int i;

	/*
	 * Process the last block (if any)
	 * We move the final 1 according to remaining input length
	 * (this will add less than 2^130 to the last input block)
	 */
	if (ctx->c_idx != 0) {
		ZERO(ctx->c + ctx->c_idx, 16 - ctx->c_idx);
		ctx->c[ctx->c_idx] = 1;
		poly_blocks(ctx, ctx->c, 1, 0);
	}

	/*
	 * check if we should subtract 2^130-5 by performing the
	 * corresponding carry propagation.
	 */
	c = 5;
	for (i = 0; i < 4; i++) {
		c  += ctx->h[i];
		c >>= 32;
	}
	c += ctx->h[4];
	c  = (c >> 2) * 5; /* shift the carry back to the beginning */
	/* c now indicates how many times we should subtract 2^130-5 (0 or 1) */
	for (i = 0; i < 4; i++) {
		c += (u64)ctx->h[i] + ctx->pad[i];
		store32_le(mac + i*4, (u32)c);
		c = c >> 32;
	}
	WIPE_CTX(ctx);
}

static void
lock_auth(u8 mac[16], const u8 auth_key[32], const u8 *ad, usize ad_size, const u8 *cipher_text, usize text_size)
{
	u8 sizes[16];                    /* Not secret, not wiped */
	poly1305_ctx poly_ctx;           /* auto wiped... */

	store64_le(sizes + 0, ad_size);
	store64_le(sizes + 8, text_size);
	poly1305_init  (&poly_ctx, auth_key);
	poly1305_update(&poly_ctx, ad         , ad_size);
	poly1305_update(&poly_ctx, zero       , gap(ad_size, 16));
	poly1305_update(&poly_ctx, cipher_text, text_size);
	poly1305_update(&poly_ctx, zero       , gap(text_size, 16));
	poly1305_update(&poly_ctx, sizes      , 16);
	poly1305_final (&poly_ctx, mac); /* ...here */
}

/* IETF */
void
chacha20poly1305init(Chacha20poly1305ctx *ctx, const uchar key[32], const uchar nonce[12])
{
	COPY(ctx->key  , key      , 32);
	COPY(ctx->nonce, nonce + 4,  8);
	ctx->counter = (u64)load32_le(nonce) << 32;
}

void
chacha20poly1305write(Chacha20poly1305ctx *ctx, uchar *out, const uchar *ad, usize adlen, const uchar *in, usize inlen)
{
	u8 auth_key[64]; /* the last 32 bytes are used for rekeying. */
	u8 *mac = out + inlen;
	chacha20_djb(auth_key, 0, 64,
			ctx->key, ctx->nonce, ctx->counter);
	chacha20_djb(out, in, inlen,
			ctx->key, ctx->nonce, ctx->counter + 1);
	lock_auth(mac, auth_key, ad, adlen, out, inlen);
	COPY(ctx->key, auth_key + 32, 32);
	WIPE_BUFFER(auth_key);
}

int
chacha20poly1305read(Chacha20poly1305ctx *ctx, uchar *out, const uchar *ad, usize adlen, const uchar *in, usize inlen)
{
	u8 auth_key[64]; /* the last 32 bytes are used for rekeying. */
	u8 real_mac[16];
	const u8 *mac = in + inlen - 16;
	int mismatch;

	if(inlen < 16)
		return 1;
	chacha20_djb(auth_key, 0, 64,
			ctx->key, ctx->nonce, ctx->counter);
	lock_auth(real_mac, auth_key, ad, adlen, in, inlen - 16);
	mismatch = verify16(mac, real_mac);
	if (!mismatch) {
		chacha20_djb(out, in, inlen - 16,
				ctx->key, ctx->nonce, ctx->counter + 1);
		COPY(ctx->key, auth_key + 32, 32);
	}
	WIPE_BUFFER(auth_key);
	WIPE_BUFFER(real_mac);
	return mismatch;
}
