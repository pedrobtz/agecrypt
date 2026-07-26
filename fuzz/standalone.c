/*
 * A minimal standalone driver for the fuzz targets, for platforms/toolchains
 * without libFuzzer (e.g. Apple clang, which ships the -fsanitize=fuzzer flag
 * but not the runtime). It loads a seed corpus, replays it once as a
 * regression check, then runs a bounded AFL-style random-mutation loop, all
 * under whatever sanitizers the target was built with.
 *
 * This is NOT coverage-guided; it is a smoke test. Real coverage-guided
 * fuzzing uses libFuzzer/AFL++ (see build.sh and README.md), typically in CI.
 *
 *   ./fuzz_decrypt <corpus-dir> [iterations]     (default 200000)
 *   AGE_FUZZ_SEED=<n> ./fuzz_decrypt corpus/decrypt   (reproducible)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define MAXLEN (1u << 20) /* 1 MiB working cap */

typedef struct { uint8_t *buf; size_t len; } Seed;

static Seed  *seeds;
static size_t nseeds;
static uint32_t rng = 0x9e3779b9u;

static uint32_t
rnd(void)
{
	uint32_t x = rng;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return rng = x;
}

static size_t
rnd_n(size_t n)
{
	return n ? (size_t)rnd() % n : 0;
}

static int
load_dir(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *e;
	char fp[4096];
	size_t cap = 16;

	if(d == NULL)
		return -1;
	nseeds = 0;
	seeds = malloc(cap * sizeof(*seeds));
	while((e = readdir(d)) != NULL) {
		FILE *f;
		long sz;
		uint8_t *b;

		if(e->d_name[0] == '.')
			continue;
		snprintf(fp, sizeof(fp), "%s/%s", path, e->d_name);
		f = fopen(fp, "rb");
		if(f == NULL)
			continue;
		fseek(f, 0, SEEK_END);
		sz = ftell(f);
		fseek(f, 0, SEEK_SET);
		if(sz < 0 || (size_t)sz > MAXLEN) {
			fclose(f);
			continue;
		}
		b = malloc(sz ? (size_t)sz : 1);
		if(fread(b, 1, (size_t)sz, f) != (size_t)sz) {
			free(b);
			fclose(f);
			continue;
		}
		fclose(f);
		if(nseeds == cap) {
			cap *= 2;
			seeds = realloc(seeds, cap * sizeof(*seeds));
		}
		seeds[nseeds].buf = b;
		seeds[nseeds].len = (size_t)sz;
		nseeds++;
	}
	closedir(d);
	return 0;
}

/* Apply one random mutation in place; return the new length (<= MAXLEN). */
static size_t
mutate(uint8_t *buf, size_t len)
{
	switch(rnd_n(7)) {
	case 0: /* bit flip */
		if(len)
			buf[rnd_n(len)] ^= (uint8_t)(1u << rnd_n(8));
		break;
	case 1: /* set random byte */
		if(len)
			buf[rnd_n(len)] = (uint8_t)rnd();
		break;
	case 2: { /* insert random bytes */
		size_t at = rnd_n(len + 1), k = 1 + rnd_n(16), i;
		if(len + k > MAXLEN)
			k = MAXLEN - len;
		memmove(buf + at + k, buf + at, len - at);
		for(i = 0; i < k; i++)
			buf[at + i] = (uint8_t)rnd();
		len += k;
		break;
	}
	case 3: /* delete a range */
		if(len > 1) {
			size_t at = rnd_n(len), k = 1 + rnd_n(len - at);
			memmove(buf + at, buf + at + k, len - at - k);
			len -= k;
		}
		break;
	case 4: /* copy a block over another (overlap-safe) */
		if(len > 1) {
			size_t k = 1 + rnd_n(len < 32 ? len : 32);
			size_t src = rnd_n(len - k + 1), dst = rnd_n(len - k + 1);
			memmove(buf + dst, buf + src, k);
		}
		break;
	case 5: /* truncate */
		if(len)
			len = rnd_n(len);
		break;
	case 6: /* splice: append part of another seed */
		if(nseeds) {
			Seed *s = &seeds[rnd_n(nseeds)];
			size_t k = s->len ? rnd_n(s->len) : 0;
			if(len + k > MAXLEN)
				k = MAXLEN - len;
			memcpy(buf + len, s->buf, k);
			len += k;
		}
		break;
	}
	return len;
}

int
main(int argc, char **argv)
{
	const char *dir = argc > 1 ? argv[1] : "corpus";
	unsigned long iters = argc > 2 ? strtoul(argv[2], NULL, 10) : 200000ul;
	const char *seedenv = getenv("AGE_FUZZ_SEED");
	uint8_t *work;
	size_t i;
	unsigned long it;

	rng = seedenv ? (uint32_t)strtoul(seedenv, NULL, 10) : (uint32_t)time(NULL);
	if(rng == 0)
		rng = 1;

	if(load_dir(dir) != 0 || nseeds == 0) {
		fprintf(stderr, "standalone-fuzz: no seeds in '%s'\n", dir);
		return 1;
	}

	/* regression: replay every committed/generated seed once */
	for(i = 0; i < nseeds; i++)
		LLVMFuzzerTestOneInput(seeds[i].buf, seeds[i].len);

	fprintf(stderr, "standalone-fuzz: %zu seeds replayed; %lu iterations (seed=%u)\n",
			nseeds, iters, rng);
	work = malloc(MAXLEN);
	for(it = 0; it < iters; it++) {
		Seed *s = &seeds[rnd_n(nseeds)];
		size_t len = s->len > MAXLEN ? MAXLEN : s->len;
		int r, rounds = 1 + (int)rnd_n(6);

		memcpy(work, s->buf, len);
		for(r = 0; r < rounds; r++)
			len = mutate(work, len);
		LLVMFuzzerTestOneInput(work, len);
		if(it && (it & 0x3ffff) == 0)
			fprintf(stderr, "  %lu iterations...\n", it);
	}
	fprintf(stderr, "standalone-fuzz: done, no crashes\n");
	free(work);
	return 0;
}
