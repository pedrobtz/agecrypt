/*
 * Based on Pascal S. de Kloe's public domain implementation:
 * https://github.com/pascaldekloe/bech32 (commit 43757af)
 */
#include "common.h"
#include "bech32.h"

/* Chartab reverses dictionary for parsing. Range [128..255] is removed. */
static const char chartab[128] = {
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	15, 99, 10, 17, 21, 20, 26, 30,  7,  5, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
	99, 29, 99, 24, 13, 25,  9,  8, 23, 99, 18, 22, 31, 27, 19, 99,
	 1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, 99, 99, 99, 99, 99,
};

/*
 * Dictionary is the lower-case character set for data encoding,
 * in which the index of each character represents its respective
 * numerical (5-bit) value.
 */
static const char *dictionary = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static usize prepare(char *s, usize *last1, int *ok);
static uint32 labelcheck(char *s, usize len, int *ok);
static uint32 check5bits(uint32 code, uint32 v);
static int decode(uchar *out, char *s, usize len, usize last1, usize *olen, uint32 *code);
static uint32 checksum(char *s, usize slen, uint32 code, int *ok);
static uint32 encode(uchar *data, usize datalen, uint32 code, uchar *out, usize *olen);
static void encodesum(uint32 code, uchar *out);

int
bech32decode(char *s, uchar *out, usize *outlen, usize *hrplen)
{
	usize slen, last1;
	uint32 code;
	int ok;

	slen = prepare(s, &last1, &ok);
	if(!ok)
		return 0;    /* ErrCaseMix */
	if(slen > 90)
		return 0;    /* ErrBig */
	if(last1 <= 0)
		return 0;    /* errNoLabel */
	if(slen - last1 < 7)
		return 0;    /* errNoCksum */
	code = labelcheck(s, last1, &ok);
	if(!ok)
		return 0;    /* errLabelChar */
	ok = decode(out, s, slen, last1, outlen, &code);
	if(!ok)
		return 0;
	code = checksum(s, slen, code, &ok);
	if(code != 1)
		return 0;    /* recovery not implemented */
	*hrplen = last1;
	return 1;
}

static usize
prepare(char *s, usize *last1, int *ok)
{
	usize i;
	int haslow = 0, hasup = 0;

	*last1 = -1;
	for(i = 0; s[i] != '\0'; i++) {
		if(s[i] >= 'a' && s[i] <= 'z') {
			haslow = 1;
		} else if(s[i] >= 'A' && s[i] <= 'Z') {
			hasup = 1;
			s[i] += 32;
		} else if(s[i] == '1') {
			*last1 = i;
		}
	}
	*ok = !(haslow && hasup);
	return i;
}

static uint32
labelcheck(char *s, usize len, int *ok)
{
	uint32 code, i;

	code = 1;
	for(i = 0; i < len; i++) {
		if(s[i] < 33 || s[i] > 126) {
			*ok = 0;
			return 0;
		}
		code = check5bits(code, s[i] >> 5);
		/* least significant bits in next loop */
	}
	code = check5bits(code, 0);
	for(i = 0; i < len; i++)
		code = check5bits(code, (uint32)s[i] & 31);
	*ok = 1;
	return code;
}

/* See the 'Checksum' subsection in BIP 0173. */
static uint32
check5bits(uint32 code, uint32 v)
{
	uint32 b;

	b = code >> 25;
	code = (code & 0x1ffffff)<<5 ^ v;
	if(b & 1)
		code ^= 0x3b6a57b2;
	if(b & 2)
		code ^= 0x26508e6d;
	if(b & 4)
		code ^= 0x1ea119fa;
	if(b & 8)
		code ^= 0x3d4233dd;
	if(b & 16)
		code ^= 0x2a1462b3;
	return code;
}

static int
decode(uchar *out, char *s, usize len, usize last1, usize *olen, uint32 *code)
{
	usize i, o;
	uint32 c = *code;
	uint32 acc = 0;
	int bits = 0;
	char v;

	for(o = 0, i = last1 + 1; i < len - 6; i++) {
		v = ((uchar)s[i] > 127) ? 99 : chartab[(uchar)s[i]];
		if(v > 31)
			return 0;  /* errDataChar */
		c = check5bits(c, v);
		acc = (acc << 5) | v;
		bits += 5;
		while(bits >= 8) {
			bits -= 8;
			out[o++] = (acc >> bits) & 0xff;
		}
	}
	*olen = o;
	*code = c;
	return 1;
}

static uint32
checksum(char *s, usize slen, uint32 code, int *ok)
{
	usize i;
	char v;

	for(i = slen - 6; i < slen; i++) {
		v = ((uchar)s[i] > 127) ? 99 : chartab[(uchar)s[i]];
		if(v > 31) {
			*ok = 0;
			return 0;
		}
		code = check5bits(code, v);
	}
	return code;
}

int
bech32encode(char *label, uchar *data, usize datalen, uchar *out)
{
	usize nbits = datalen * 8, l, labellen, olen;
	uint32 code;
	int ok;

	labellen = strlen(label);
	l = 7 + labellen + (nbits + 4) / 5;
	if(l > 90)
		return 0;    /* ErrBig */
	memcpy(out, label, labellen);
	out[labellen] = '1';
	code = labelcheck(label, labellen, &ok);
	if(!ok)
		return 0;    /* errLabelChar */
	code = encode(data, datalen, code, out + labellen + 1, &olen);
	encodesum(code, out + labellen + 1 + olen);
	return 1;
}

static uint32
encode(uchar *data, usize datalen, uint32 code, uchar *out, usize *olen)
{
	uchar *start = out;
	usize i;
	uint8 acc = 0, v;
	int nbits = 0;

	for(i = 0; i < datalen; i++) {
		v = acc | (data[i] >> (8 - 5 + nbits));
		code = check5bits(code, v);
		*(out++) = dictionary[v];
		nbits = (8 - 5 + nbits);
		if(nbits > 5) {
			v = data[i] << (8 - nbits);
			v >>= (8 - nbits);
			v >>= nbits - 5;
			code = check5bits(code, v);
			*(out++) = dictionary[v];
			nbits -= 5;
		}
		acc = data[i] << (8 - nbits);
		acc >>= 3;
	}
	if(nbits > 0) {
		code = check5bits(code, acc);
		*(out++) = dictionary[acc];
	}
	*olen = out - start;
	return code;
}

static void
encodesum(uint32 code, uchar *out)
{
	int i;

	for(i = 0; i < 6; i++)
		code = check5bits(code, 0);
	code ^= 1;
	*(out++) = dictionary[code >> 25 & 31];
	*(out++) = dictionary[code >> 20 & 31];
	*(out++) = dictionary[code >> 15 & 31];
	*(out++) = dictionary[code >> 10 & 31];
	*(out++) = dictionary[code >>  5 & 31];
	*(out++) = dictionary[code >>  0 & 31];
	*out = '\0';
}
