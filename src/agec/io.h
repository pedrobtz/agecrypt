#define IOBUFSIZE 8*1024
#define IOABUFRAWSIZE 48*256
#define IOABUFSIZE B64EBUFLEN(IOABUFRAWSIZE) + B64EBUFLEN(IOABUFRAWSIZE) / 64
#define IOABUFREADSIZE 65*126

typedef struct Obuf Obuf;
struct Obuf {
	int fd;
	usize cur;
	int isarmor;
	union {
		uchar buf[IOBUFSIZE];
		uchar abuf[IOABUFRAWSIZE];
	} buf;
};

/* To keep record of read bytes for MAC */
typedef struct Record Record;
struct Record {
	uchar *buf;
	usize len, capacity;
};

typedef struct Ibuf Ibuf;
struct Ibuf {
	int fd;
	int eof;
	int isarmor;
	int recording;
	const char *recfail;
	usize cur, size;
	usize acur, asize;
	int aendpos;
	uchar buf[IOBUFSIZE];
	uchar abuf[IOABUFREADSIZE];
	Record rec;
};

extern const char armorfirst[36];
extern const char armorlast[34];

void ibinit(Ibuf *b, int fd);
void ibfree(Ibuf *b);
ssize bwrite(Obuf *b, void *buf, usize n);
ssize bflush(Obuf *b);
ssize bread(Ibuf *b, void *buf, usize n);
ssize bpeek(Ibuf *b, char *c);
uchar *recstop(Ibuf *b, usize *len);
ssize writeall(int fd, const void *buf, usize nbytes);
