#include "common.h"
#include "util.h"
#include "memio.h"

#include <unistd.h>

/*
 * A tiny fixed-capacity table of in-memory streams. R evaluates .Call() code
 * single-threaded, and each encrypt/decrypt uses at most one read and one
 * write stream at a time, so a small table with no locking is sufficient.
 */

#define MEMFD_MAX 8

typedef struct MemFile MemFile;
struct MemFile {
	int      used;
	int      write;      /* 1 sink, 0 source */
	uchar   *data;       /* sink: owned/grown; source: borrowed */
	usize    len;        /* valid bytes */
	usize    cap;        /* allocated (sink only) */
	usize    pos;        /* read cursor (source only) */
};

static MemFile memtab[MEMFD_MAX];

/* virtual fd <-> table index: vfd = -2 - i, so vfd in [-2 - (MAX-1), -2] */
static int
vfd_to_index(int vfd)
{
	int i;

	if(vfd > -2)
		return -1;
	i = -2 - vfd;
	if(i < 0 || i >= MEMFD_MAX || !memtab[i].used)
		return -1;
	return i;
}

static int
memalloc(void)
{
	int i;

	for(i = 0; i < MEMFD_MAX; i++) {
		if(!memtab[i].used) {
			memtab[i].used = 1;
			memtab[i].write = 0;
			memtab[i].data = NULL;
			memtab[i].len = memtab[i].cap = memtab[i].pos = 0;
			return i;
		}
	}
	return -1;
}

int
memopen_read(const uchar *data, usize len)
{
	int i;

	i = memalloc();
	if(i == -1)
		return -1;
	memtab[i].write = 0;
	memtab[i].data = (uchar *)data;   /* borrowed, never written or freed */
	memtab[i].len = len;
	memtab[i].pos = 0;
	return -2 - i;
}

int
memopen_write(void)
{
	int i;

	i = memalloc();
	if(i == -1)
		return -1;
	memtab[i].write = 1;
	return -2 - i;
}

uchar *
memdata(int vfd, usize *len)
{
	int i;

	i = vfd_to_index(vfd);
	if(i == -1) {
		*len = 0;
		return NULL;
	}
	*len = memtab[i].len;
	return memtab[i].data;
}

void
memclose(int vfd)
{
	int i;

	i = vfd_to_index(vfd);
	if(i == -1)
		return;
	if(memtab[i].write && memtab[i].data != NULL) {
		wipe(memtab[i].data, memtab[i].cap);
		free(memtab[i].data);
	}
	memtab[i].used = 0;
	memtab[i].data = NULL;
	memtab[i].len = memtab[i].cap = memtab[i].pos = 0;
}

static ssize
memread(int i, void *buf, usize nbytes)
{
	usize avail;

	avail = memtab[i].len - memtab[i].pos;
	if(avail == 0)
		return 0;                 /* EOF */
	if(nbytes > avail)
		nbytes = avail;
	memcpy(buf, memtab[i].data + memtab[i].pos, nbytes);
	memtab[i].pos += nbytes;
	return (ssize)nbytes;
}

static ssize
memwrite(int i, const void *buf, usize nbytes)
{
	usize need, ncap;
	uchar *p;

	need = memtab[i].len + nbytes;
	if(need < memtab[i].len)
		return -1;                /* size_t overflow */
	if(need > memtab[i].cap) {
		ncap = memtab[i].cap ? memtab[i].cap : 4096;
		while(ncap < need) {
			if(ncap > (usize)-1 / 2)
				return -1;
			ncap *= 2;
		}
		p = realloc(memtab[i].data, ncap);
		if(p == NULL)
			return -1;
		memtab[i].data = p;
		memtab[i].cap = ncap;
	}
	memcpy(memtab[i].data + memtab[i].len, buf, nbytes);
	memtab[i].len += nbytes;
	return (ssize)nbytes;
}

ssize
ageread(int fd, void *buf, usize nbytes)
{
	int i;

	if(fd >= 0)
		return read(fd, buf, nbytes);
	i = vfd_to_index(fd);
	if(i == -1)
		return -1;
	return memread(i, buf, nbytes);
}

ssize
agewrite(int fd, const void *buf, usize nbytes)
{
	int i;

	if(fd >= 0)
		return write(fd, buf, nbytes);
	i = vfd_to_index(fd);
	if(i == -1 || !memtab[i].write)
		return -1;
	return memwrite(i, buf, nbytes);
}
