/*
 * Fuzz target: the passphrase (scrypt) decrypt path.
 *
 * Same idea as fuzz_decrypt.c, but drives age_decipher_passphrase() with a
 * fixed passphrase ("password", as used by the C2SP scrypt vectors) so scrypt
 * seeds authenticate. Exercises scrypt stanza parsing, the work-factor bound,
 * and the shared payload path. Build under ASan/UBSan.
 */
#include <stdint.h>
#include <stddef.h>

#include "agec.h"
#include "agecore.h"
#include "memio.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	Ibuf ib;
	Obuf ob;
	int vin, vout;

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

	(void)age_decipher_passphrase(&ib, &ob, "password");

	ibfree(&ib);
	memclose(vin);
	memclose(vout);
	return 0;
}
