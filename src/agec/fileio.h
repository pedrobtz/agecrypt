#ifndef AGE_FILEIO_H
#define AGE_FILEIO_H

/*
 * Helpers for writing output files atomically: create a private temporary
 * file next to the destination, write into it, and only rename it into place
 * once the whole operation has succeeded. This keeps a failed or interrupted
 * operation from destroying a pre-existing destination, never exposes a
 * partial result at the final path, and gives key files owner-only mode.
 *
 * Must be included after "common.h" (for uchar/usize/ssize).
 */

/*
 * Create and open a fresh, owner-only (0600) temp file in the same directory
 * as `outp` (so a later rename stays on one filesystem). The chosen path is
 * written into `tmpout`, which must have room for strlen(outp) + 24 bytes.
 * Returns an open write fd, or -1 with errno set.
 */
int age_open_temp(const char *outp, char *tmpout, usize tmpcap);

/* Flush a descriptor's data to stable storage. Returns 0, or -1 with errno. */
int age_fsync(int fd);

/*
 * Atomically move `tmp` onto `dst`. If `overwrite` is nonzero, replace any
 * existing `dst`; otherwise fail (errno EEXIST) when `dst` already exists,
 * without a check-then-write race. Returns 0, or -1 with errno set.
 */
int age_move(const char *tmp, const char *dst, int overwrite);

#endif
