
int base64_encode(char *base64, const unsigned char *binary, size_t length);
int base64_decode(unsigned char *binary, size_t *binary_length, const char *base64, size_t base64_length);
