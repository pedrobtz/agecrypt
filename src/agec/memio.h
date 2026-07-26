#ifndef AGE_MEMIO_H
#define AGE_MEMIO_H

/*
 * Memory-backed virtual file descriptors.
 *
 * The vendored agec I/O layer (io.c) reads and writes through int file
 * descriptors. To operate on in-memory R buffers instead of files we hand
 * out negative "virtual" descriptors (<= -2; -1 stays the error sentinel and
 * 0/1/2 stay the standard streams). ageread()/agewrite() dispatch: a negative
 * fd is served from the memfd table, any other fd goes to the real syscall.
 */

int    memopen_read(const uchar *data, usize len); /* borrow data (not copied) */
int    memopen_write(void);                         /* growable sink            */
uchar *memdata(int vfd, usize *len);                /* current bytes of a sink  */
void   memclose(int vfd);

ssize ageread(int fd, void *buf, usize nbytes);
ssize agewrite(int fd, const void *buf, usize nbytes);

#endif
