/*
 * Public domain ref10 implementation of curve25519 from SUPERCOP.
 * Extracted from monocypher-4.0.2.
 */
#include "common.h"
#include "../util.h"
#include "../crypto.h"

#define COPY(dst, src, size)       memcpy(dst, src, size * sizeof((*dst)))
#define ZERO(buf, size)            memset(buf, 0, size * sizeof((*buf)))
#define WIPE_BUFFER(buffer)        wipe(buffer, sizeof(buffer))

typedef int8   i8;
typedef uint8  u8;
typedef int16  i16;
typedef uint32 u32;
typedef int32  i32;
typedef int64  i64;
typedef uint64 u64;
typedef i32 fe[10];

const uchar curve25519basepoint[32] = {
	9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static u32
load24_le(const u8 s[3])
{
	return
		((u32)s[0] <<  0) |
		((u32)s[1] <<  8) |
		((u32)s[2] << 16);
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

static int
neq0(u64 diff)
{
	/* constant time comparison to zero */
	/* return diff != 0 ? -1 : 0 */
	u64 half = (diff >> 32) | ((u32)diff);
	return (1 & ((half - 1) >> 32)) - 1;
}

static u64
x16(const u8 a[16], const u8 b[16])
{
	return (load64_le(a + 0) ^ load64_le(b + 0))
		|  (load64_le(a + 8) ^ load64_le(b + 8));
}

static u64 x32(const u8 a[32],const u8 b[32]){return x16(a,b)| x16(a+16, b+16);}

static int
crypto_verify32(const u8 a[32], const u8 b[32])
{
	return neq0(x32(a, b));
}

/* sqrt(-1) field constant */
static const fe sqrtm1  = {
	-32595792, -7943725, 9377950, 3500415, 12389472,
	-272473, -25146209, -2005654, 326686, 11406482,
};

static void fe_0(fe h) {           ZERO(h  , 10); }
static void fe_1(fe h) { h[0] = 1; ZERO(h+1,  9); }

static void
fe_copy(fe h, const fe f)
{
	int i;

	for(i = 0; i < 10; i++)
		h[i] = f[i];
}

static void
fe_neg(fe h, const fe f)
{
	int i;

	for (i = 0; i < 10; i++)
		h[i] = -f[i];
}

static void
fe_add(fe h, const fe f, const fe g)
{
	int i;

	for (i = 0; i < 10; i++)
		h[i] = f[i] + g[i];
}

static void
fe_sub(fe h, const fe f, const fe g)
{
	int i;

	for (i = 0; i < 10; i++)
		h[i] = f[i] - g[i];
}

static void
fe_cswap(fe f, fe g, int b)
{
	i32 mask = -b; /* -1 = 0xffffffff */
	int i;

	for (i = 0; i < 10; i++) {
	        i32 x = (f[i] ^ g[i]) & mask;
	        f[i] = f[i] ^ x;
	        g[i] = g[i] ^ x;
	}
}

static void
fe_ccopy(fe f, const fe g, int b)
{
	i32 mask = -b; /* -1 = 0xffffffff */
	int i;

	for (i = 0; i < 10; i++) {
		i32 x = (f[i] ^ g[i]) & mask;
		f[i] = f[i] ^ x;
	}
}

/*
 * Signed carry propagation
 * ------------------------
 *
 * Let t be a number.  It can be uniquely decomposed thus:
 *
 *    t = h*2^26 + l
 *    such that -2^25 <= l < 2^25
 *
 * Let c = (t + 2^25) / 2^26            (rounded down)
 *     c = (h*2^26 + l + 2^25) / 2^26   (rounded down)
 *     c =  h   +   (l + 2^25) / 2^26   (rounded down)
 *     c =  h                           (exactly)
 * Because 0 <= l + 2^25 < 2^26
 *
 * Let u = t          - c*2^26
 *     u = h*2^26 + l - h*2^26
 *     u = l
 * Therefore, -2^25 <= u < 2^25
 *
 * Additionally, if |t| < x, then |h| < x/2^26 (rounded down)
 *
 * Notations:
 * - In C, 1<<25 means 2^25.
 * - In C, x>>25 means floor(x / (2^25)).
 * - All of the above applies with 25 & 24 as well as 26 & 25.
 *
 *
 * Note on negative right shifts
 * -----------------------------
 *
 * In C, x >> n, where x is a negative integer, is implementation
 * defined.  In practice, all platforms do arithmetic shift, which is
 * equivalent to division by 2^26, rounded down.  Some compilers, like
 * GCC, even guarantee it.
 *
 * If we ever stumble upon a platform that does not propagate the sign
 * bit (we won't), visible failures will show at the slightest test, and
 * the signed shifts can be replaced by the following:
 *
 *     typedef struct { i64 x:39; } s25;
 *     typedef struct { i64 x:38; } s26;
 *     i64 shift25(i64 x) { s25 s; s.x = ((u64)x)>>25; return s.x; }
 *     i64 shift26(i64 x) { s26 s; s.x = ((u64)x)>>26; return s.x; }
 *
 * Current compilers cannot optimise this, causing a 30% drop in
 * performance.  Fairly expensive for something that never happens.
 *
 *
 * Precondition
 * ------------
 *
 * |t0|       < 2^63
 * |t1|..|t9| < 2^62
 *
 * Algorithm
 * ---------
 * c   = t0 + 2^25 / 2^26   -- |c|  <= 2^36
 * t0 -= c * 2^26           -- |t0| <= 2^25
 * t1 += c                  -- |t1| <= 2^63
 *
 * c   = t4 + 2^25 / 2^26   -- |c|  <= 2^36
 * t4 -= c * 2^26           -- |t4| <= 2^25
 * t5 += c                  -- |t5| <= 2^63
 *
 * c   = t1 + 2^24 / 2^25   -- |c|  <= 2^38
 * t1 -= c * 2^25           -- |t1| <= 2^24
 * t2 += c                  -- |t2| <= 2^63
 *
 * c   = t5 + 2^24 / 2^25   -- |c|  <= 2^38
 * t5 -= c * 2^25           -- |t5| <= 2^24
 * t6 += c                  -- |t6| <= 2^63
 *
 * c   = t2 + 2^25 / 2^26   -- |c|  <= 2^37
 * t2 -= c * 2^26           -- |t2| <= 2^25        < 1.1 * 2^25  (final t2)
 * t3 += c                  -- |t3| <= 2^63
 *
 * c   = t6 + 2^25 / 2^26   -- |c|  <= 2^37
 * t6 -= c * 2^26           -- |t6| <= 2^25        < 1.1 * 2^25  (final t6)
 * t7 += c                  -- |t7| <= 2^63
 *
 * c   = t3 + 2^24 / 2^25   -- |c|  <= 2^38
 * t3 -= c * 2^25           -- |t3| <= 2^24        < 1.1 * 2^24  (final t3)
 * t4 += c                  -- |t4| <= 2^25 + 2^38 < 2^39
 *
 * c   = t7 + 2^24 / 2^25   -- |c|  <= 2^38
 * t7 -= c * 2^25           -- |t7| <= 2^24        < 1.1 * 2^24  (final t7)
 * t8 += c                  -- |t8| <= 2^63
 *
 * c   = t4 + 2^25 / 2^26   -- |c|  <= 2^13
 * t4 -= c * 2^26           -- |t4| <= 2^25        < 1.1 * 2^25  (final t4)
 * t5 += c                  -- |t5| <= 2^24 + 2^13 < 1.1 * 2^24  (final t5)
 *
 * c   = t8 + 2^25 / 2^26   -- |c|  <= 2^37
 * t8 -= c * 2^26           -- |t8| <= 2^25        < 1.1 * 2^25  (final t8)
 * t9 += c                  -- |t9| <= 2^63
 *
 * c   = t9 + 2^24 / 2^25   -- |c|  <= 2^38
 * t9 -= c * 2^25           -- |t9| <= 2^24        < 1.1 * 2^24  (final t9)
 * t0 += c * 19             -- |t0| <= 2^25 + 2^38*19 < 2^44
 *
 * c   = t0 + 2^25 / 2^26   -- |c|  <= 2^18
 * t0 -= c * 2^26           -- |t0| <= 2^25        < 1.1 * 2^25  (final t0)
 * t1 += c                  -- |t1| <= 2^24 + 2^18 < 1.1 * 2^24  (final t1)
 *
 * Postcondition
 * -------------
 *   |t0|, |t2|, |t4|, |t6|, |t8|  <  1.1 * 2^25
 *   |t1|, |t3|, |t5|, |t7|, |t9|  <  1.1 * 2^24
 */
#define FE_CARRY        \
	i64 c; \
	c = (t0 + ((i64)1<<25)) >> 26;  t0 -= c * ((i64)1 << 26);  t1 += c; \
	c = (t4 + ((i64)1<<25)) >> 26;  t4 -= c * ((i64)1 << 26);  t5 += c; \
	c = (t1 + ((i64)1<<24)) >> 25;  t1 -= c * ((i64)1 << 25);  t2 += c; \
	c = (t5 + ((i64)1<<24)) >> 25;  t5 -= c * ((i64)1 << 25);  t6 += c; \
	c = (t2 + ((i64)1<<25)) >> 26;  t2 -= c * ((i64)1 << 26);  t3 += c; \
	c = (t6 + ((i64)1<<25)) >> 26;  t6 -= c * ((i64)1 << 26);  t7 += c; \
	c = (t3 + ((i64)1<<24)) >> 25;  t3 -= c * ((i64)1 << 25);  t4 += c; \
	c = (t7 + ((i64)1<<24)) >> 25;  t7 -= c * ((i64)1 << 25);  t8 += c; \
	c = (t4 + ((i64)1<<25)) >> 26;  t4 -= c * ((i64)1 << 26);  t5 += c; \
	c = (t8 + ((i64)1<<25)) >> 26;  t8 -= c * ((i64)1 << 26);  t9 += c; \
	c = (t9 + ((i64)1<<24)) >> 25;  t9 -= c * ((i64)1 << 25);  t0 += c*19; \
	c = (t0 + ((i64)1<<25)) >> 26;  t0 -= c * ((i64)1 << 26);  t1 += c; \
	h[0]=(i32)t0;  h[1]=(i32)t1; h[2]=(i32)t2; h[3]=(i32)t3; h[4]=(i32)t4; \
	h[5]=(i32)t5;  h[6]=(i32)t6; h[7]=(i32)t7; h[8]=(i32)t8; h[9]=(i32)t9

/*
 * Decodes a field element from a byte buffer.
 * mask specifies how many bits we ignore.
 * Traditionally we ignore 1. It's useful for EdDSA,
 * which uses that bit to denote the sign of x.
 * Elligator however uses positive representatives,
 * which means ignoring 2 bits instead.
 */
static void
fe_frombytes_mask(fe h, const u8 s[32], uint nb_mask)
{
	u32 mask = 0xffffff >> nb_mask;
	i64 t0 =  load32_le(s);                    /* t0 < 2^32 */
	i64 t1 =  load24_le(s +  4) << 6;          /* t1 < 2^30 */
	i64 t2 =  load24_le(s +  7) << 5;          /* t2 < 2^29 */
	i64 t3 =  load24_le(s + 10) << 3;          /* t3 < 2^27 */
	i64 t4 =  load24_le(s + 13) << 2;          /* t4 < 2^26 */
	i64 t5 =  load32_le(s + 16);               /* t5 < 2^32 */
	i64 t6 =  load24_le(s + 20) << 7;          /* t6 < 2^31 */
	i64 t7 =  load24_le(s + 23) << 5;          /* t7 < 2^29 */
	i64 t8 =  load24_le(s + 26) << 4;          /* t8 < 2^28 */
	i64 t9 = (load24_le(s + 29) & mask) << 2;  /* t9 < 2^25 */
	FE_CARRY;                                  /* Carry precondition OK */
}

static void
fe_frombytes(fe h, const u8 s[32])
{
	fe_frombytes_mask(h, s, 1);
}

/*
 * Precondition
 *   |h[0]|, |h[2]|, |h[4]|, |h[6]|, |h[8]|  <  1.1 * 2^25
 *   |h[1]|, |h[3]|, |h[5]|, |h[7]|, |h[9]|  <  1.1 * 2^24
 *
 * Therefore, |h| < 2^255-19
 * There are two possibilities:
 *
 * - If h is positive, all we need to do is reduce its individual
 *   limbs down to their tight positive range.
 * - If h is negative, we also need to add 2^255-19 to it.
 *   Or just remove 19 and chop off any excess bit.
 */
static void
fe_tobytes(u8 s[32], const fe h)
{
	i32 t[10], q;
	int i;

	COPY(t, h, 10);
	q = (19 * t[9] + (((i32) 1) << 24)) >> 25;

	/*
	 *                 |t9|                    < 1.1 * 2^24
	 *  -1.1 * 2^24  <  t9                     < 1.1 * 2^24
	 *  -21  * 2^24  <  19 * t9                < 21  * 2^24
	 *  -2^29        <  19 * t9 + 2^24         < 2^29
	 *  -2^29 / 2^25 < (19 * t9 + 2^24) / 2^25 < 2^29 / 2^25
	 *  -16          < (19 * t9 + 2^24) / 2^25 < 16
	 */
	for (i = 0; i < 5; i++) {
		q += t[2*i  ]; q >>= 26; /* q = 0 or -1 */
		q += t[2*i+1]; q >>= 25; /* q = 0 or -1 */
	}
	/*
	 * q =  0 iff h >= 0
	 * q = -1 iff h <  0
	 * Adding q * 19 to h reduces h to its proper range.
	 */
	q *= 19;  /* Shift carry back to the beginning */
	for (i = 0; i < 5; i++) {
		t[i*2  ]+=q; q = t[i*2  ] >> 26; t[i*2  ] -= q * ((i32)1 << 26);
		t[i*2+1]+=q; q = t[i*2+1] >> 25; t[i*2+1] -= q * ((i32)1 << 25);
	}
	/* h is now fully reduced, and q represents the excess bit. */

	store32_le(s +  0, ((u32)t[0] >>  0) | ((u32)t[1] << 26));
	store32_le(s +  4, ((u32)t[1] >>  6) | ((u32)t[2] << 19));
	store32_le(s +  8, ((u32)t[2] >> 13) | ((u32)t[3] << 13));
	store32_le(s + 12, ((u32)t[3] >> 19) | ((u32)t[4] <<  6));
	store32_le(s + 16, ((u32)t[5] >>  0) | ((u32)t[6] << 25));
	store32_le(s + 20, ((u32)t[6] >>  7) | ((u32)t[7] << 19));
	store32_le(s + 24, ((u32)t[7] >> 13) | ((u32)t[8] << 12));
	store32_le(s + 28, ((u32)t[8] >> 20) | ((u32)t[9] <<  6));

	WIPE_BUFFER(t);
}

/*
 * Precondition
 * -------------
 *   |f0|, |f2|, |f4|, |f6|, |f8|  <  1.65 * 2^26
 *   |f1|, |f3|, |f5|, |f7|, |f9|  <  1.65 * 2^25
 *
 *   |g0|, |g2|, |g4|, |g6|, |g8|  <  1.65 * 2^26
 *   |g1|, |g3|, |g5|, |g7|, |g9|  <  1.65 * 2^25
 */
static void
fe_mul_small(fe h, const fe f, i32 g)
{
	i64 t0 = f[0] * (i64) g;  i64 t1 = f[1] * (i64) g;
	i64 t2 = f[2] * (i64) g;  i64 t3 = f[3] * (i64) g;
	i64 t4 = f[4] * (i64) g;  i64 t5 = f[5] * (i64) g;
	i64 t6 = f[6] * (i64) g;  i64 t7 = f[7] * (i64) g;
	i64 t8 = f[8] * (i64) g;  i64 t9 = f[9] * (i64) g;
	/* |t0|, |t2|, |t4|, |t6|, |t8|  <  1.65 * 2^26 * 2^31  < 2^58 */
	/* |t1|, |t3|, |t5|, |t7|, |t9|  <  1.65 * 2^25 * 2^31  < 2^57 */

	FE_CARRY; /* Carry precondition OK */
}

/*
 * Precondition
 * -------------
 *   |f0|, |f2|, |f4|, |f6|, |f8|  <  1.65 * 2^26
 *   |f1|, |f3|, |f5|, |f7|, |f9|  <  1.65 * 2^25
 *
 *   |g0|, |g2|, |g4|, |g6|, |g8|  <  1.65 * 2^26
 *   |g1|, |g3|, |g5|, |g7|, |g9|  <  1.65 * 2^25
 */
static void
fe_mul(fe h, const fe f, const fe g)
{
	/*
	 * Everything is unrolled and put in temporary variables.
	 * We could roll the loop, but that would make curve25519 twice as slow.
	 */
	i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 =f[3]; i32 f4 =f[4];
	i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 =f[8]; i32 f9 =f[9];
	i32 g0 = g[0]; i32 g1 = g[1]; i32 g2 = g[2]; i32 g3 =g[3]; i32 g4 =g[4];
	i32 g5 = g[5]; i32 g6 = g[6]; i32 g7 = g[7]; i32 g8 =g[8]; i32 g9 =g[9];
	i32 F1 = f1*2; i32 F3 = f3*2; i32 F5 = f5*2; i32 F7 =f7*2; i32 F9 =f9*2;
	i32 G1 = g1*19;  i32 G2 = g2*19;  i32 G3 = g3*19;
	i32 G4 = g4*19;  i32 G5 = g5*19;  i32 G6 = g6*19;
	i32 G7 = g7*19;  i32 G8 = g8*19;  i32 G9 = g9*19;
	/*
	 * |F1|, |F3|, |F5|, |F7|, |F9|  <  1.65 * 2^26
	 * |G0|, |G2|, |G4|, |G6|, |G8|  <  2^31
	 * |G1|, |G3|, |G5|, |G7|, |G9|  <  2^30
	 */

	i64 t0 = f0*(i64)g0 + F1*(i64)G9 + f2*(i64)G8 + F3*(i64)G7 + f4*(i64)G6
	       + F5*(i64)G5 + f6*(i64)G4 + F7*(i64)G3 + f8*(i64)G2 + F9*(i64)G1;
	i64 t1 = f0*(i64)g1 + f1*(i64)g0 + f2*(i64)G9 + f3*(i64)G8 + f4*(i64)G7
	       + f5*(i64)G6 + f6*(i64)G5 + f7*(i64)G4 + f8*(i64)G3 + f9*(i64)G2;
	i64 t2 = f0*(i64)g2 + F1*(i64)g1 + f2*(i64)g0 + F3*(i64)G9 + f4*(i64)G8
	       + F5*(i64)G7 + f6*(i64)G6 + F7*(i64)G5 + f8*(i64)G4 + F9*(i64)G3;
	i64 t3 = f0*(i64)g3 + f1*(i64)g2 + f2*(i64)g1 + f3*(i64)g0 + f4*(i64)G9
	       + f5*(i64)G8 + f6*(i64)G7 + f7*(i64)G6 + f8*(i64)G5 + f9*(i64)G4;
	i64 t4 = f0*(i64)g4 + F1*(i64)g3 + f2*(i64)g2 + F3*(i64)g1 + f4*(i64)g0
	       + F5*(i64)G9 + f6*(i64)G8 + F7*(i64)G7 + f8*(i64)G6 + F9*(i64)G5;
	i64 t5 = f0*(i64)g5 + f1*(i64)g4 + f2*(i64)g3 + f3*(i64)g2 + f4*(i64)g1
	       + f5*(i64)g0 + f6*(i64)G9 + f7*(i64)G8 + f8*(i64)G7 + f9*(i64)G6;
	i64 t6 = f0*(i64)g6 + F1*(i64)g5 + f2*(i64)g4 + F3*(i64)g3 + f4*(i64)g2
	       + F5*(i64)g1 + f6*(i64)g0 + F7*(i64)G9 + f8*(i64)G8 + F9*(i64)G7;
	i64 t7 = f0*(i64)g7 + f1*(i64)g6 + f2*(i64)g5 + f3*(i64)g4 + f4*(i64)g3
	       + f5*(i64)g2 + f6*(i64)g1 + f7*(i64)g0 + f8*(i64)G9 + f9*(i64)G8;
	i64 t8 = f0*(i64)g8 + F1*(i64)g7 + f2*(i64)g6 + F3*(i64)g5 + f4*(i64)g4
	       + F5*(i64)g3 + f6*(i64)g2 + F7*(i64)g1 + f8*(i64)g0 + F9*(i64)G9;
	i64 t9 = f0*(i64)g9 + f1*(i64)g8 + f2*(i64)g7 + f3*(i64)g6 + f4*(i64)g5
	       + f5*(i64)g4 + f6*(i64)g3 + f7*(i64)g2 + f8*(i64)g1 + f9*(i64)g0;
	/*
	 * t0 < 0.67 * 2^61
	 * t1 < 0.41 * 2^61
	 * t2 < 0.52 * 2^61
	 * t3 < 0.32 * 2^61
	 * t4 < 0.38 * 2^61
	 * t5 < 0.22 * 2^61
	 * t6 < 0.23 * 2^61
	 * t7 < 0.13 * 2^61
	 * t8 < 0.09 * 2^61
	 * t9 < 0.03 * 2^61
	 */

	FE_CARRY; /* Everything below 2^62, Carry precondition OK */
}

/*
 * Precondition
 * -------------
 *   |f0|, |f2|, |f4|, |f6|, |f8|  <  1.65 * 2^26
 *   |f1|, |f3|, |f5|, |f7|, |f9|  <  1.65 * 2^25
 *
 * Note: we could use fe_mul() for this, but this is significantly faster
 */
static void
fe_sq(fe h, const fe f)
{
	i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 =f[3]; i32 f4 =f[4];
	i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 =f[8]; i32 f9 =f[9];
	i32 f0_2  = f0*2;  i32 f1_2  = f1*2;  i32 f2_2  = f2*2; i32 f3_2 = f3*2;
	i32 f4_2  = f4*2;  i32 f5_2  = f5*2;  i32 f6_2  = f6*2; i32 f7_2 = f7*2;
	i32 f5_38 = f5*38;  i32 f6_19 = f6*19;  i32 f7_38 = f7*38;
	i32 f8_19 = f8*19;  i32 f9_38 = f9*38;
	/*
	 * |f0_2| , |f2_2| , |f4_2| , |f6_2| , |f8_2|  <  1.65 * 2^27
	 * |f1_2| , |f3_2| , |f5_2| , |f7_2| , |f9_2|  <  1.65 * 2^26
	 * |f5_38|, |f6_19|, |f7_38|, |f8_19|, |f9_38| <  2^31
	 */

	i64 t0 = f0  *(i64)f0    + f1_2*(i64)f9_38 + f2_2*(i64)f8_19
	       + f3_2*(i64)f7_38 + f4_2*(i64)f6_19 + f5  *(i64)f5_38;
	i64 t1 = f0_2*(i64)f1    + f2  *(i64)f9_38 + f3_2*(i64)f8_19
	       + f4  *(i64)f7_38 + f5_2*(i64)f6_19;
	i64 t2 = f0_2*(i64)f2    + f1_2*(i64)f1    + f3_2*(i64)f9_38
	       + f4_2*(i64)f8_19 + f5_2*(i64)f7_38 + f6  *(i64)f6_19;
	i64 t3 = f0_2*(i64)f3    + f1_2*(i64)f2    + f4  *(i64)f9_38
	       + f5_2*(i64)f8_19 + f6  *(i64)f7_38;
	i64 t4 = f0_2*(i64)f4    + f1_2*(i64)f3_2  + f2  *(i64)f2
	       + f5_2*(i64)f9_38 + f6_2*(i64)f8_19 + f7  *(i64)f7_38;
	i64 t5 = f0_2*(i64)f5    + f1_2*(i64)f4    + f2_2*(i64)f3
	       + f6  *(i64)f9_38 + f7_2*(i64)f8_19;
	i64 t6 = f0_2*(i64)f6    + f1_2*(i64)f5_2  + f2_2*(i64)f4
	       + f3_2*(i64)f3    + f7_2*(i64)f9_38 + f8  *(i64)f8_19;
	i64 t7 = f0_2*(i64)f7    + f1_2*(i64)f6    + f2_2*(i64)f5
	       + f3_2*(i64)f4    + f8  *(i64)f9_38;
	i64 t8 = f0_2*(i64)f8    + f1_2*(i64)f7_2  + f2_2*(i64)f6
	       + f3_2*(i64)f5_2  + f4  *(i64)f4    + f9  *(i64)f9_38;
	i64 t9 = f0_2*(i64)f9    + f1_2*(i64)f8    + f2_2*(i64)f7
	       + f3_2*(i64)f6    + f4  *(i64)f5_2;
	/*
	 * t0 < 0.67 * 2^61
	 * t1 < 0.41 * 2^61
	 * t2 < 0.52 * 2^61
	 * t3 < 0.32 * 2^61
	 * t4 < 0.38 * 2^61
	 * t5 < 0.22 * 2^61
	 * t6 < 0.23 * 2^61
	 * t7 < 0.13 * 2^61
	 * t8 < 0.09 * 2^61
	 * t9 < 0.03 * 2^61
	 */

	FE_CARRY;
}

/* Returns 1 if equal, 0 if not equal */
static int
fe_isequal(const fe f, const fe g)
{
	u8 fs[32];
	u8 gs[32];
	int isdifferent;

	fe_tobytes(fs, f);
	fe_tobytes(gs, g);
	isdifferent = crypto_verify32(fs, gs);
	WIPE_BUFFER(fs);
	WIPE_BUFFER(gs);
	return 1 + isdifferent;
}

/*
 * Inverse square root.
 * Returns true if x is a square, false otherwise.
 * After the call:
 *   isr = sqrt(1/x)        if x is a non-zero square.
 *   isr = sqrt(sqrt(-1)/x) if x is not a square.
 *   isr = 0                if x is zero.
 * We do not guarantee the sign of the square root.
 *
 * Notes:
 * Let quartic = x^((p-1)/4)
 *
 * x^((p-1)/2) = chi(x)
 * quartic^2   = chi(x)
 * quartic     = sqrt(chi(x))
 * quartic     = 1 or -1 or sqrt(-1) or -sqrt(-1)
 *
 * Note that x is a square if quartic is 1 or -1
 * There are 4 cases to consider:
 *
 * if   quartic         = 1  (x is a square)
 * then x^((p-1)/4)     = 1
 *      x^((p-5)/4) * x = 1
 *      x^((p-5)/4)     = 1/x
 *      x^((p-5)/8)     = sqrt(1/x) or -sqrt(1/x)
 *
 * if   quartic                = -1  (x is a square)
 * then x^((p-1)/4)            = -1
 *      x^((p-5)/4) * x        = -1
 *      x^((p-5)/4)            = -1/x
 *      x^((p-5)/8)            = sqrt(-1)   / sqrt(x)
 *      x^((p-5)/8) * sqrt(-1) = sqrt(-1)^2 / sqrt(x)
 *      x^((p-5)/8) * sqrt(-1) = -1/sqrt(x)
 *      x^((p-5)/8) * sqrt(-1) = -sqrt(1/x) or sqrt(1/x)
 *
 * if   quartic         = sqrt(-1)  (x is not a square)
 * then x^((p-1)/4)     = sqrt(-1)
 *      x^((p-5)/4) * x = sqrt(-1)
 *      x^((p-5)/4)     = sqrt(-1)/x
 *      x^((p-5)/8)     = sqrt(sqrt(-1)/x) or -sqrt(sqrt(-1)/x)
 *
 * Note that the product of two non-squares is always a square:
 *   For any non-squares a and b, chi(a) = -1 and chi(b) = -1.
 *   Since chi(x) = x^((p-1)/2), chi(a)*chi(b) = chi(a*b) = 1.
 *   Therefore a*b is a square.
 *
 *   Since sqrt(-1) and x are both non-squares, their product is a
 *   square, and we can compute their square root.
 *
 * if   quartic                = -sqrt(-1)  (x is not a square)
 * then x^((p-1)/4)            = -sqrt(-1)
 *      x^((p-5)/4) * x        = -sqrt(-1)
 *      x^((p-5)/4)            = -sqrt(-1)/x
 *      x^((p-5)/8)            = sqrt(-sqrt(-1)/x)
 *      x^((p-5)/8)            = sqrt( sqrt(-1)/x) * sqrt(-1)
 *      x^((p-5)/8) * sqrt(-1) = sqrt( sqrt(-1)/x) * sqrt(-1)^2
 *      x^((p-5)/8) * sqrt(-1) = sqrt( sqrt(-1)/x) * -1
 *      x^((p-5)/8) * sqrt(-1) = -sqrt(sqrt(-1)/x) or sqrt(sqrt(-1)/x)
 */
static int
invsqrt(fe isr, const fe x)
{
	fe t0, t1, t2;
	i32 *quartic, *check;
	int i, z0, p1, m1, ms;

	/*
	 * t0 = x^((p-5)/8)
	 * Can be achieved with a simple double & add ladder,
	 * but it would be slower.
	 */
	fe_sq(t0, x);
	fe_sq(t1,t0);                     fe_sq(t1, t1);    fe_mul(t1, x, t1);
	fe_mul(t0, t0, t1);
	fe_sq(t0, t0);                                      fe_mul(t0, t1, t0);
	fe_sq(t1, t0); for(i=1; i<  5;i++){ fe_sq(t1, t1); }  fe_mul(t0, t1, t0);
	fe_sq(t1, t0); for(i=1; i< 10;i++){ fe_sq(t1, t1); }  fe_mul(t1, t1, t0);
	fe_sq(t2, t1); for(i=1; i< 20;i++){ fe_sq(t2, t2); }  fe_mul(t1, t2, t1);
	fe_sq(t1, t1); for(i=1; i< 10;i++){ fe_sq(t1, t1); }  fe_mul(t0, t1, t0);
	fe_sq(t1, t0); for(i=1; i< 50;i++){ fe_sq(t1, t1); }  fe_mul(t1, t1, t0);
	fe_sq(t2, t1); for(i=1; i<100;i++){ fe_sq(t2, t2); }  fe_mul(t1, t2, t1);
	fe_sq(t1, t1); for(i=1; i< 50;i++){ fe_sq(t1, t1); }  fe_mul(t0, t1, t0);
	fe_sq(t0, t0); for(i=1; i<  2;i++){ fe_sq(t0, t0); }  fe_mul(t0, t0, x);

	/* quartic = x^((p-1)/4) */
	quartic = t1;
	fe_sq (quartic, t0);
	fe_mul(quartic, quartic, x);

	check = t2;
	fe_0  (check);          z0 = fe_isequal(x      , check);
	fe_1  (check);          p1 = fe_isequal(quartic, check);
	fe_neg(check, check );  m1 = fe_isequal(quartic, check);
	fe_neg(check, sqrtm1);  ms = fe_isequal(quartic, check);

	/*
	 * if quartic == -1 or sqrt(-1)
	 * then  isr = x^((p-1)/4) * sqrt(-1)
	 * else  isr = x^((p-1)/4)
	 */
	fe_mul(isr, t0, sqrtm1);
	fe_ccopy(isr, t0, 1 - (m1 | ms));

	WIPE_BUFFER(t0);
	WIPE_BUFFER(t1);
	WIPE_BUFFER(t2);
	return p1 | m1 | z0;
}

/*
 * Inverse in terms of inverse square root.
 * Requires two additional squarings to get rid of the sign.
 *
 *   1/x = x * (+invsqrt(x^2))^2
 *       = x * (-invsqrt(x^2))^2
 *
 * A fully optimised exponentiation by p-1 would save 6 field
 * multiplications, but it would require more code.
 */
static void
fe_invert(fe out, const fe x)
{
	fe tmp;
	fe_sq(tmp, x);
	invsqrt(tmp, tmp);
	fe_sq(tmp, tmp);
	fe_mul(out, tmp, x);
	WIPE_BUFFER(tmp);
}

/* trim a scalar for scalar multiplication */
void
trim_scalar(u8 out[32], const u8 in[32])
{
	COPY(out, in, 32);
	out[ 0] &= 248;
	out[31] &= 127;
	out[31] |= 64;
}

/* get bit from scalar at position i */
static int
scalar_bit(const u8 s[32], int i)
{
	if (i < 0) { return 0; } /* handle -1 for sliding windows */
	return (s[i>>3] >> (i&7)) & 1;
}

/* X-25519. Taken from SUPERCOP's ref10 implementation. */
static void
scalarmult(u8 q[32], const u8 scalar[32], const u8 p[32], int nb_bits)
{
	/* computes the scalar product */
	fe x1;
	/* computes the actual scalar product (the result is in x2 and z2) */
	fe x2, z2, x3, z3, t0, t1;
	int pos, swap;

	fe_frombytes(x1, p);
	/*
	 *  Montgomery ladder
	 * In projective coordinates, to avoid divisions: x = X / Z
	 * We don't care about the y coordinate, it's only 1 bit of information
	 */
	fe_1(x2);        fe_0(z2); /* "zero" point */
	fe_copy(x3, x1); fe_1(z3); /* "one"  point */
	swap = 0;
	for (pos = nb_bits-1; pos >= 0; --pos) {
		/* constant time conditional swap before ladder step */
		int b = scalar_bit(scalar, pos);
		/* xor trick avoids swapping at the end of the loop */
		swap ^= b;
		fe_cswap(x2, x3, swap);
		fe_cswap(z2, z3, swap);
		swap = b;  /* anticipates one last swap after the loop */

		/*
		 * Montgomery ladder step: replaces (P2, P3) by (P2*2, P2+P3)
		 * with differential addition
		 */
		fe_sub(t0, x3, z3);
		fe_sub(t1, x2, z2);
		fe_add(x2, x2, z2);
		fe_add(z2, x3, z3);
		fe_mul(z3, t0, x2);
		fe_mul(z2, z2, t1);
		fe_sq (t0, t1    );
		fe_sq (t1, x2    );
		fe_add(x3, z3, z2);
		fe_sub(z2, z3, z2);
		fe_mul(x2, t1, t0);
		fe_sub(t1, t1, t0);
		fe_sq (z2, z2    );
		fe_mul_small(z3, t1, 121666);
		fe_sq (x3, x3    );
		fe_add(t0, t0, z3);
		fe_mul(z3, x1, z2);
		fe_mul(z2, t1, t0);
	}
	/*
	 * last swap is necessary to compensate for the xor trick
	 * Note: after this swap, P3 == P2 + P1.
	 */
	fe_cswap(x2, x3, swap);
	fe_cswap(z2, z3, swap);

	/* normalises the coordinates: x == X / Z */
	fe_invert(z2, z2);
	fe_mul(x2, x2, z2);
	fe_tobytes(q, x2);

	WIPE_BUFFER(x1);
	WIPE_BUFFER(x2);  WIPE_BUFFER(z2);  WIPE_BUFFER(t0);
	WIPE_BUFFER(x3);  WIPE_BUFFER(z3);  WIPE_BUFFER(t1);
}

static int
notzero(uchar in[32])
{
	int i;
	uchar c;

	for(i = 0, c = 0; i < 32; i++)
		c |= in[i];
	return c;
}

int
x25519(uchar out[32], const uchar priv[32], const uchar pub[32])
{
	/* restrict the possible scalar values */
	u8 e[32];

	trim_scalar(e, priv);
	scalarmult(out, e, pub, 255);
	WIPE_BUFFER(e);
	return notzero(out);
}

int
x25519pub(uchar out[32], uchar priv[32])
{
	return x25519(out, priv, curve25519basepoint);
}
