#define SHA256_DIGEST_LENGTH 32

typedef struct Sha256ctx Sha256ctx;
struct Sha256ctx {
	uint64 len;    /* processed message length */
	uint32 h[8];   /* hash state */
	uchar buf[64]; /* message block buffer */
};

typedef struct Hmacsha256ctx Hmacsha256ctx;
struct Hmacsha256ctx {
	Sha256ctx inner, outer;
};

typedef struct Chacha20poly1305ctx Chacha20poly1305ctx;
struct Chacha20poly1305ctx {
	uint64 counter;
	uchar key[32];
	uchar nonce[8];
};

extern const uchar curve25519basepoint[32];

int randombuf(uchar *buf, int len);
int x25519(uchar out[32], const uchar priv[32], const uchar pub[32]);
int x25519pub(uchar out[32], uchar priv[32]);
void sha256init(Sha256ctx *ctx);
void sha256update(Sha256ctx *ctx, const void *m, unsigned long len);
/* state is ruined after sum, keep a copy if multiple sum is needed */
/* part of the message might be left in ctx, zero it if secrecy is needed */
void sha256final(Sha256ctx *ctx, uchar md[SHA256_DIGEST_LENGTH]);
void hmacsha256(const uchar *k, usize klen, const uchar *in, usize inlen, uchar out[32]);
void hmacsha256init(Hmacsha256ctx *ctx, const uchar *k, usize klen);
void hmacsha256update(Hmacsha256ctx *ctx, const uchar *in, usize inlen);
void hmacsha256final(Hmacsha256ctx *ctx, uchar out[32]);
void hkdfsha256(const uchar *ikm, usize ikmlen, const uchar *salt, usize saltlen, const uchar *info, usize infolen, uchar out[32]);
void chacha20poly1305init(Chacha20poly1305ctx *ctx, const uchar key[32], const uchar nonce[12]);
void chacha20poly1305write(Chacha20poly1305ctx *ctx, uchar *out, const uchar *ad, usize adlen, const uchar *in, usize inlen);
int chacha20poly1305read(Chacha20poly1305ctx *ctx, uchar *out, const uchar *ad, usize adlen, const uchar *in, usize inlen);
const char *scrypt(const uchar *pass, usize passlen, const uchar *salt, usize saltlen, uint32 n, uint32 r, uint32 p, uchar *out, usize bytes);
