#include "common.h"
#include "util.h"

#include <errno.h>
#include <string.h>

/*
 * Portable platform layer replacing agec's unix/util.c + unix/random.c.
 * Contains no interactive prompts, no exit(), no writes to std streams, and
 * no OpenSSL dependency, so the code is safe to link into an R package.
 */

/* Referenced as `extern const char *argv0` by the vendored util.c. */
const char *argv0 = "age";

/* Defined in the vendored util.c. */
extern char ebuf[EBUFSIZE];

const char *
eget(void)
{
	if(*ebuf)
		return ebuf;
	return strerror(errno);
}

/*
 * Cryptographically secure random bytes. Returns nonzero on success, 0 on
 * failure (matching agec's randombuf contract). No external library is used.
 */
#if defined(_WIN32)

#include <windows.h>
#include <bcrypt.h>

int
randombuf(uchar *buf, int len)
{
	NTSTATUS s;

	if(len < 0)
		return 0;
	s = BCryptGenRandom(NULL, buf, (ULONG)len,
			BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	return BCRYPT_SUCCESS(s) ? 1 : 0;
}

#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || \
      defined(__NetBSD__) || defined(__DragonFly__)

#include <stdlib.h>

int
randombuf(uchar *buf, int len)
{
	if(len < 0)
		return 0;
	arc4random_buf(buf, (size_t)len);
	return 1;
}

#else /* Linux and other systems with getentropy(2) */

#include <sys/random.h>

int
randombuf(uchar *buf, int len)
{
	int off, n;

	if(len < 0)
		return 0;
	for(off = 0; off < len; off += n) {
		n = (len - off > 256) ? 256 : len - off;  /* getentropy cap */
		if(getentropy(buf + off, (size_t)n) != 0)
			return 0;
	}
	return 1;
}

#endif
