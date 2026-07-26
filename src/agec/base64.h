/* Length of buffer for encoded string with no pads and no line feeds */
#define B64EBUFLEN(l) ((((l) / 3) * 4) + (((l) % 3) ? ((l) % 3 + 1) : 0))

void base64encode(uchar *in, uchar *out, usize len, usize *outlen, int pad);
int  base64decode(uchar *in, uchar *out, usize len, usize *outlen, int pad);
