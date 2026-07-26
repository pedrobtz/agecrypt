#define R_NO_REMAP
#include <R.h>
#include <Rinternals.h>
#include <R_ext/Rdynload.h>
#include <R_ext/Visibility.h>

extern SEXP age_c_keygen(void);
extern SEXP age_c_identity_parse(SEXP secrets);
extern SEXP age_c_identity_pubkeys(SEXP ext);
extern SEXP age_c_identity_write(SEXP ext, SEXP path, SEXP created, SEXP overwrite);
extern SEXP age_c_identity_free(SEXP ext);
extern SEXP age_c_encrypt(SEXP data, SEXP recipients, SEXP armor);
extern SEXP age_c_decrypt(SEXP data, SEXP ext);
extern SEXP age_c_encrypt_path(SEXP inpath, SEXP outpath, SEXP recipients, SEXP armor, SEXP overwrite);
extern SEXP age_c_decrypt_path(SEXP inpath, SEXP outpath, SEXP ext, SEXP overwrite);
extern SEXP age_c_encrypt_passphrase(SEXP data, SEXP pass, SEXP armor, SEXP logn);
extern SEXP age_c_decrypt_passphrase(SEXP data, SEXP pass);
extern SEXP age_c_encrypt_path_passphrase(SEXP inpath, SEXP outpath, SEXP pass, SEXP armor, SEXP logn, SEXP overwrite);
extern SEXP age_c_decrypt_path_passphrase(SEXP inpath, SEXP outpath, SEXP pass, SEXP overwrite);

static const R_CallMethodDef CallEntries[] = {
	{"age_c_keygen",          (DL_FUNC) &age_c_keygen,          0},
	{"age_c_identity_parse",  (DL_FUNC) &age_c_identity_parse,  1},
	{"age_c_identity_pubkeys",(DL_FUNC) &age_c_identity_pubkeys,1},
	{"age_c_identity_write",  (DL_FUNC) &age_c_identity_write,  4},
	{"age_c_identity_free",   (DL_FUNC) &age_c_identity_free,   1},
	{"age_c_encrypt",         (DL_FUNC) &age_c_encrypt,         3},
	{"age_c_decrypt",         (DL_FUNC) &age_c_decrypt,         2},
	{"age_c_encrypt_path",    (DL_FUNC) &age_c_encrypt_path,    5},
	{"age_c_decrypt_path",    (DL_FUNC) &age_c_decrypt_path,    4},
	{"age_c_encrypt_passphrase",      (DL_FUNC) &age_c_encrypt_passphrase,      4},
	{"age_c_decrypt_passphrase",      (DL_FUNC) &age_c_decrypt_passphrase,      2},
	{"age_c_encrypt_path_passphrase", (DL_FUNC) &age_c_encrypt_path_passphrase, 6},
	{"age_c_decrypt_path_passphrase", (DL_FUNC) &age_c_decrypt_path_passphrase, 4},
	{NULL, NULL, 0}
};

void attribute_visible
R_init_agecrypt(DllInfo *dll)
{
	R_registerRoutines(dll, NULL, CallEntries, NULL, NULL);
	R_useDynamicSymbols(dll, FALSE);
	R_forceSymbols(dll, TRUE);
}
