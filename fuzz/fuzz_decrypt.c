/*
 * Fuzz target: the X25519 decrypt path.
 *
 * Feeds arbitrary bytes to age_decipher() as ciphertext, exercising the whole
 * parsing surface an attacker controls -- ASCII-armor framing, base64, bech32,
 * header stanzas, the header MAC, and the STREAM payload. A fixed identity is
 * used so that some inputs authenticate and reach the payload logic; malformed
 * inputs exercise the parsers and error paths. Build under ASan/UBSan; the
 * sanitizers are the detectors, this target just drives inputs.
 *
 * libFuzzer entry point (also called by the standalone driver in standalone.c).
 */
#include <stdint.h>
#include <stddef.h>

#include "agec.h"
#include "agecore.h"
#include "memio.h"

/* Identity from the C2SP "x25519"/"armor" success vectors, so seeds that use
 * it authenticate and give deep coverage. */
static uchar g_priv[32];

static void
init_key(void)
{
	static int done = 0;
	char bech[] =
		"AGE-SECRET-KEY-1XMWWC06LY3EE5RYTXM9MFLAZ2U56JJJ36S0MYPDRWSVLUL66MV4QX3S7F6";

	if(done)
		return;
	done = 1;
	/* On parse failure g_priv stays all-zero: still a usable scalar, so the
	 * parser is exercised even if nothing authenticates. */
	(void)x25519privkey(bech, g_priv);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	Ibuf ib;
	Obuf ob;
	int vin, vout;

	init_key();
	vin = memopen_read((const uchar *)data, size);
	vout = memopen_write();
	if(vin == -1 || vout == -1) {
		if(vin != -1) memclose(vin);
		if(vout != -1) memclose(vout);
		return 0;
	}
	ibinit(&ib, vin);
	ob.fd = vout;
	ob.cur = 0;
	ob.isarmor = 0;

	(void)age_decipher(&ib, &ob, g_priv, 1);

	ibfree(&ib);
	memclose(vin);
	memclose(vout);
	return 0;
}
