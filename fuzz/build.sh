#!/bin/sh
# Build the fuzz targets under AddressSanitizer + UndefinedBehaviorSanitizer.
#
# If the toolchain provides libFuzzer (-fsanitize=fuzzer), the targets are
# coverage-guided libFuzzer binaries. Otherwise (e.g. Apple clang, which ships
# the flag but not the runtime) they are linked against standalone.c, a small
# non-coverage-guided mutation driver -- enough for a local smoke test.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
src="$here/../src"
CC=${CC:-clang}
INC="-I$src/agec -I$src/agec/crypto -DNDEBUG"
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1"

libs="$src/memio.c $src/platform.c $src/agec/agecore.c \
$src/agec/base64.c $src/agec/bech32.c $src/agec/header.c $src/agec/io.c \
$src/agec/keyenc.c $src/agec/parse.c $src/agec/payload.c $src/agec/scrypt.c \
$src/agec/util.c $src/agec/x25519.c \
$src/agec/crypto/chacha20poly1305.c $src/agec/crypto/curve25519.c \
$src/agec/crypto/hkdf.c $src/agec/crypto/hmac.c $src/agec/crypto/scrypt.c \
$src/agec/crypto/sha256.c"

if printf 'int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return 0;}\n' \
   | $CC -x c -fsanitize=fuzzer,address -o /dev/null - 2>/dev/null; then
	mode=libFuzzer
	drv=""
	fuzzflags="-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g -O1"
else
	mode=standalone
	drv="$here/standalone.c"
	fuzzflags="$SAN"
fi
echo "fuzz build mode: $mode"

for t in decrypt passphrase; do
	# shellcheck disable=SC2086
	$CC $fuzzflags $INC $drv "$here/fuzz_$t.c" $libs -o "$here/fuzz_$t"
	echo "built $here/fuzz_$t"
done
