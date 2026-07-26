typedef struct Header Header;
struct Header {
	uchar *data;
	usize len;
	usize allocated;
};

const char *hdrinit(Header *h);
const char *hdrappend(Header *h, char *fmt, ...);
void hdrmac(uchar *data, usize len, uchar filekey[16], char *out, usize *outlen);
void mac(uchar *data, usize len, uchar filekey[16], uchar out[32]);
