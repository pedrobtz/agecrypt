typedef struct Header Header;
struct Header {
	Obuf *ob;
	Hmacsha256ctx ctx;
};

void hdrinit(Header *h, uchar filekey[16], Obuf *ob);
const char *hdrappend(Header *h, char *fmt, ...);
void hdrfinish(Header *h, char mac[B64EBUFLEN(32)], usize *maclen);
void mac(uchar *data, usize len, uchar filekey[16], uchar out[32]);
