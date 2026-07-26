#define EBUFSIZE 512

void eset(const char *err);
const char *eget(void);
const char *ewrap(const char *outer, const char *inner);
const char *esys(const char *outer);
const char *efmt(const char *fmt, ...);
void die(const char *msg);
void exitstatus(char *st);
void *reallocarr(void *p, usize nmemb, usize size);
const char *getpassword(const char *prompt, char *buf, usize len);
void wipe(void *buf, usize len);
const char *xprogname(const char *arg0, const char *def);
int xisatty(int fd);
