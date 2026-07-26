#include "common.h"
#include "crypto.h"
#include "fileio.h"

#include <errno.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#endif

#define TMPSUFFIX 21   /* ".age-" + 16 hex chars, plus a NUL -> 22 bytes */

int
age_open_temp(const char *outp, char *tmpout, usize tmpcap)
{
	static const char hex[] = "0123456789abcdef";
	usize olen = strlen(outp), i;
	uchar r[8];
	int fd, tries, flags;

	if(tmpcap < olen + TMPSUFFIX + 1) {
		errno = ENAMETOOLONG;
		return -1;
	}
	flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_BINARY
	flags |= O_BINARY;             /* Windows: no CRLF translation */
#endif
	for(tries = 0; tries < 16; tries++) {
		if(!randombuf(r, sizeof(r))) {
			errno = EIO;
			return -1;
		}
		memcpy(tmpout, outp, olen);
		memcpy(tmpout + olen, ".age-", 5);
		for(i = 0; i < sizeof(r); i++) {
			tmpout[olen + 5 + i * 2]     = hex[r[i] >> 4];
			tmpout[olen + 5 + i * 2 + 1] = hex[r[i] & 0x0f];
		}
		tmpout[olen + TMPSUFFIX] = '\0';
		fd = open(tmpout, flags, 0600);
		if(fd != -1)
			return fd;
		if(errno != EEXIST)
			return -1;
	}
	return -1;
}

int
age_fsync(int fd)
{
#ifdef _WIN32
	return _commit(fd);
#else
	return fsync(fd);
#endif
}

int
age_move(const char *tmp, const char *dst, int overwrite)
{
#ifdef _WIN32
	DWORD flags = MOVEFILE_WRITE_THROUGH;

	if(overwrite)
		flags |= MOVEFILE_REPLACE_EXISTING;
	if(MoveFileExA(tmp, dst, flags))
		return 0;
	/* without REPLACE_EXISTING, a present destination is a no-clobber error */
	if(!overwrite) {
		DWORD e = GetLastError();
		if(e == ERROR_ALREADY_EXISTS || e == ERROR_FILE_EXISTS)
			errno = EEXIST;
	}
	return -1;
#else
	if(overwrite)
		return rename(tmp, dst);
	/*
	 * Atomic no-clobber: link() creates dst only if it does not already
	 * exist (EEXIST otherwise), closing the check-then-write race that a
	 * plain rename() would leave open.
	 */
	if(link(tmp, dst) == 0) {
		unlink(tmp);
		return 0;
	}
	if(errno == EEXIST)
		return -1;
	/*
	 * Some filesystems do not support hard links. Fall back to a
	 * best-effort existence check plus rename (non-atomic, but only on
	 * those filesystems).
	 */
	if(access(dst, F_OK) == 0) {
		errno = EEXIST;
		return -1;
	}
	return rename(tmp, dst);
#endif
}
