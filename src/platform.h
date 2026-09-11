#ifndef AGE_PLATFORM_H
#define AGE_PLATFORM_H

/*
 * Package-owned platform layer (src/platform.c), replacing agec's unix/util.c
 * and unix/random.c.
 *
 * Must be included after "common.h" (for uchar) and "util.h" (for EBUFSIZE).
 */

/*
 * Reset the shared agec error buffer.
 *
 * agec keeps a single process-global message buffer (`ebuf` in src/agec/util.c)
 * and eget() falls back to it whenever it is non-empty. Nothing in agec ever
 * clears it, so without this a message left behind by one operation is reported
 * by the next failure that did not set one of its own -- e.g. a write error
 * surfacing the previous call's "error parsing header: ..." instead of
 * strerror(errno). Every native entry point calls this first, which makes the
 * buffer genuinely operation-local, as binding.c's concurrency note assumes.
 */
void eclear(void);

#endif
