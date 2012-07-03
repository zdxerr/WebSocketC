
#ifndef _sha1_h
#define _sha1_h

#define SHA1_DIGEST_SIZE 20

int sha1(unsigned char *out, const unsigned char *in, size_t length);

#endif
