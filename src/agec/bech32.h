/* out size must be at least strlen(s) - 8 */
int bech32decode(char *s, uchar *out, usize *outlen, usize *hrplen);

/* out size must be at least strlen(label) + datalen + 8 */
int bech32encode(char *label, uchar *data, usize datalen, uchar *out);
