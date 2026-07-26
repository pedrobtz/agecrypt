typedef struct X25519arg X25519arg;
struct X25519arg {
	uchar share[32];
	uchar body[32];
};

const char *x25519stanza(Header *h, uchar filekey[16], uchar pubkey[32]);
int x25519pubkey(char *bech, uchar pubkey[32]);
int x25519privkey(char bech[74+1], uchar privkey[32]);
int x25519getkey(uchar k[16], X25519arg *arg, uchar privkey[32], const char **err);
