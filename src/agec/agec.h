#ifndef AGE_AGEC_H
#define AGE_AGEC_H

/*
 * Umbrella header for the vendored agec sources. The individual agec headers
 * carry no include guards and depend on inclusion order (e.g. x25519.h uses
 * the Header type from header.h; io.h uses B64EBUFLEN from base64.h). This
 * file includes them exactly once, in the order the agec .c files use, so
 * downstream code can pull in the whole surface with a single guarded include.
 */

#include "common.h"
#include "base64.h"
#include "crypto.h"
#include "bech32.h"
#include "header.h"
#include "scrypt.h"
#include "x25519.h"
#include "keyenc.h"
#include "io.h"
#include "parse.h"
#include "payload.h"
#include "util.h"

#endif
