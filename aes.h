void aes_encrypt_128(unsigned char *plainText, unsigned char *cipherText, const unsigned char *key);
void AES_128_CBC_Enc(unsigned char *plainText, unsigned char *cipherText, const unsigned char *key, unsigned char *iv, int len);
void AES_128_CBC_Dec(unsigned char *cipherText, unsigned char *plainText, const unsigned char *key, unsigned char *iv, int len);
void AES_128_Transform(int Nr, const unsigned char *key, unsigned char *plainText, unsigned char *cipherText);
