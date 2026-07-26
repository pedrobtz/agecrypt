typedef struct Scryptarg Scryptarg;
struct Scryptarg {
	uchar salt[16];
	uchar body[32];
	int cost;
};

const char *scryptstanza(Header *h, uchar filekey[16], char *pass);
const char *scryptstanzacost(Header *h, uchar filekey[16], char *pass, uint cost);
int scryptgetkey(uchar k[16], Scryptarg *arg, char *pass, const char **err);
