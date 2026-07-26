/*
 * Extracted from public domain implementation "scrypt-jane":
 * https://github.com/floodyberry/scrypt-jane (commit 0ab6125)
 */
#include "common.h"
#include "util.h"
#include "crypto.h"

#define DIGESTSIZE 32
#define BLOCKBYTES 64
#define BLOCKWORDS (BLOCKBYTES / 4)

#define ROTL32(a,b) (((a) << (b)) | ((a) >> (32 - b)))
#define U32TO8_BE(p, v)                                           \
	(p)[0] = (uchar)((v) >> 24); (p)[1] = (uchar)((v) >> 16); \
	(p)[2] = (uchar)((v) >>  8); (p)[3] = (uchar)((v)      );
#define U32_SWAP(v) {                                                 \
	(v) = (((v) << 8) & 0xFF00FF00 ) | (((v) >> 8) & 0xFF00FF );  \
	(v) = ((v) << 16) | ((v) >> 16);                              \
}

typedef struct Alignedalloc {
	uchar *mem, *ptr;
} Alignedalloc;

typedef uint32 mixword;

static Alignedalloc
alloc(uint64 size, const char **err)
{
	static const usize maxalloc = (usize)-1;
        Alignedalloc aa;

        size += BLOCKBYTES - 1;
        if(size > maxalloc)
		*err = "not enough address space to allocate required memory";
	aa.mem = malloc((usize)size);
	aa.ptr = (uchar *)(((usize)aa.mem + (BLOCKBYTES-1)) & ~(BLOCKBYTES-1));
	if(!aa.mem)
		*err = eget();
	return aa;
}


static void
pbkdf2(const uchar *pass, usize passlen, const uchar *salt, usize saltlen, uint64 n, uchar *out, usize bytes)
{
	Hmacsha256ctx hmacpw, hmacpwsalt, work;
	uchar ti[DIGESTSIZE], u[DIGESTSIZE];
	uchar be[4];
	uint32 i, j, blocks;
	uint64 c;

	/*
	 * bytes must be <= (0xffffffff - (DIGESTSIZE - 1)), which
	 * they will always be under scrypt
	 */
	/* hmac(pass, ...) */
	hmacsha256init(&hmacpw, pass, passlen);
	/* hmac(pass, salt...) */
	hmacpwsalt = hmacpw;
	hmacsha256update(&hmacpwsalt, salt, saltlen);
	blocks = ((uint32)bytes + (DIGESTSIZE - 1)) / DIGESTSIZE;
	for(i = 1; i <= blocks; i++) {
		/* U1 = hmac(pass, salt || be(i)) */
		U32TO8_BE(be, i);
		work = hmacpwsalt;
		hmacsha256update(&work, be, 4);
		hmacsha256final(&work, ti);
		memcpy(u, ti, sizeof(u));
		/* T[i] = U1 ^ U2 ^ U3... */
		for (c = 0; c < n - 1; c++) {
			/* UX = hmac(pass, U{X-1}) */
			work = hmacpw;
			hmacsha256update(&work, u, DIGESTSIZE);
			hmacsha256final(&work, u);
			/* T[i] ^= UX */
			for(j = 0; j < sizeof(u); j++)
				ti[j] ^= u[j];
		}
		memcpy(out, ti, (bytes > DIGESTSIZE) ? DIGESTSIZE : bytes);
		out += DIGESTSIZE;
		bytes -= DIGESTSIZE;
        }
	wipe(ti, sizeof(ti));
	wipe(u, sizeof(u));
	wipe(&hmacpw, sizeof(hmacpw));
	wipe(&hmacpwsalt, sizeof(hmacpwsalt));
}

#define QUARTER(a,b,c,d) \
		t = a+d; t = ROTL32(t,  7); b ^= t; \
		t = b+a; t = ROTL32(t,  9); c ^= t; \
		t = c+b; t = ROTL32(t, 13); d ^= t; \
		t = d+c; t = ROTL32(t, 18); a ^= t;

static void
salsa(uint32 state[16])
{
	usize rounds = 8;
	uint32 x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,t;

	x0 = state[0];
	x1 = state[1];
	x2 = state[2];
	x3 = state[3];
	x4 = state[4];
	x5 = state[5];
	x6 = state[6];
	x7 = state[7];
	x8 = state[8];
	x9 = state[9];
	x10 = state[10];
	x11 = state[11];
	x12 = state[12];
	x13 = state[13];
	x14 = state[14];
	x15 = state[15];
	for (; rounds; rounds -= 2) {
		QUARTER( x0, x4, x8,x12)
		QUARTER( x5, x9,x13, x1)
		QUARTER(x10,x14, x2, x6)
		QUARTER(x15, x3, x7,x11)
		QUARTER( x0, x1, x2, x3)
		QUARTER( x5, x6, x7, x4)
		QUARTER(x10,x11, x8, x9)
		QUARTER(x15,x12,x13,x14)
	}
	state[0] += x0;
	state[1] += x1;
	state[2] += x2;
	state[3] += x3;
	state[4] += x4;
	state[5] += x5;
	state[6] += x6;
	state[7] += x7;
	state[8] += x8;
	state[9] += x9;
	state[10] += x10;
	state[11] += x11;
	state[12] += x12;
	state[13] += x13;
	state[14] += x14;
	state[15] += x15;
}

/* returns a pointer to item i, where item is len mixword's long */
static mixword *
itemp(mixword *base, mixword i, mixword len)
{
	return base + (i * len);
}

/* returns a pointer to block i */
static mixword *
blockp(mixword *base, mixword i)
{
	return base + (i * BLOCKWORDS);
}

static void
chunkmix(mixword *bout, mixword *bin, mixword *bxor, uint32 r)
{
	mixword x[BLOCKWORDS], *block;
	uint32 i, j, blocksperchunk = r * 2, half = 0;

	/* 1: X = B_{2r - 1} */
	block = blockp(bin, blocksperchunk - 1);
	for(i = 0; i < BLOCKWORDS; i++)
		x[i] = block[i];
	if(bxor) {
		block = blockp(bxor, blocksperchunk - 1);
		for(i = 0; i < BLOCKWORDS; i++)
			x[i] ^= block[i];
        }
	/* 2: for i = 0 to 2r - 1 do */
	for (i = 0; i < blocksperchunk; i++, half ^= r) {
		/* 3: X = H(X ^ B_i) */
		block = blockp(bin, i);
		for(j = 0; j < BLOCKWORDS; j++)
			x[j] ^= block[j];
		if(bxor) {
			block = blockp(bxor, i);
			for(j = 0; j < BLOCKWORDS; j++)
				x[j] ^= block[j];
		}
		salsa(x);
		/* 4: Y_i = X */
		/* 6: B'[0..r-1] = Y_even */
		/* 6: B'[r..2r-1] = Y_odd */
		block = blockp(bout, (i / 2) + half);
		for(j = 0; j < BLOCKWORDS; j++)
			block[j] = x[j];
	}
}

static void
convertendian(mixword *blocks, usize nblocks)
{
	static const union { uchar b[2]; uint16 w; } endian_test = {{1,0}};
	usize i;

	if(endian_test.w == 0x100) {
		nblocks *= BLOCKWORDS;
                for(i = 0; i < nblocks; i++)
			U32_SWAP(blocks[i]);
	}
}

static void
romix(mixword *x, mixword *y, mixword *v, uint32 n, uint32 r)
{
	uint32 i, j, chunkWords = (uint32)(BLOCKWORDS * r * 2);
	mixword *block = v;

	convertendian(x, r * 2);

	/* 1: X = B */
	/* implicit */

	/* 2: for i = 0 to N - 1 do */
	memcpy(block, x, chunkWords * sizeof(mixword));
	for(i = 0; i < n - 1; i++, block += chunkWords) {
		/* 3: V_i = X */
		/* 4: X = H(X) */
		chunkmix(block + chunkWords, block, NULL, r);
        }
	chunkmix(x, block, NULL, r);

	/* 6: for i = 0 to N - 1 do */
	for (i = 0; i < n; i += 2) {
		/* 7: j = Integerify(X) % N */
		j = x[chunkWords - BLOCKWORDS] & (n - 1);

		/* 8: X = H(Y ^ V_j) */
		chunkmix(y, x, itemp(v, j, chunkWords), r);

		/* 7: j = Integerify(Y) % N */
		j = y[chunkWords - BLOCKWORDS] & (n - 1);

		/* 8: X = H(Y ^ V_j) */
		chunkmix(x, y, itemp(v, j, chunkWords), r);
	}

	/* 10: B' = X */
	/* implicit */

	convertendian(x, r * 2);
}

const char *
scrypt(const uchar *pass, usize passlen, const uchar *salt, usize saltlen, uint32 n, uint32 r, uint32 p, uchar *out, usize bytes)
{
	Alignedalloc yx, v;
	const char *err = NULL;
	uchar *x, *y;
	uint32 chunk_bytes, i;

	chunk_bytes = BLOCKBYTES * r * 2;
	v = alloc((uint64)n * chunk_bytes, &err);
	if(err)
		return err;
	yx = alloc((p + 1) * chunk_bytes, &err);
	if(err)
		return err;

	/* 1: X = PBKDF2(pass, salt) */
	y = yx.ptr;
	x = y + chunk_bytes;
	pbkdf2(pass, passlen, salt, saltlen, 1, x, chunk_bytes * p);

	/* 2: X = ROMix(X) */
	for(i = 0; i < p; i++) {
		romix((mixword *)(x + (chunk_bytes * i)), (mixword *)y,
				(mixword *)v.ptr, n, r);
	}
	/* 3: Out = PBKDF2(pass, X) */
	pbkdf2(pass, passlen, x, chunk_bytes * p, 1, out, bytes);

	wipe(yx.ptr, (p + 1) * chunk_bytes);
	free(v.mem);
	free(yx.mem);
	return NULL;
}
