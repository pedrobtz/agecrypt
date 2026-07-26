enum StanzaType {
	SCRYPT,
	X25519,
	UNKNOWN
};

typedef struct Stanza Stanza;
struct Stanza {
	enum StanzaType type;
	union {
		Scryptarg scrypt;
		X25519arg x25519;
	} arg;
};

const char *getversion(Ibuf *in);
const char *getstanza(Ibuf *in, Stanza *s, int *end);
const char *getmac(Ibuf *in, uchar mac[32]);
const char *getplnonce(Ibuf *in, uchar plnonce[16]);
