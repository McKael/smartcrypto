int generateServerHello(const char *userId, const char *pin,
	char *hello_out, size_t len, char *aes_key_out, char *hash_out);
int parseClientHello(const char *clientHello, const char *hashText,
	const char *aesKeyText, const char *userId,
	char *skprime_out, char *ctx_out);


#define ERR_SC_PIN          1
#define ERR_SC_FIRST_FLAG   2
#define ERR_SC_SECOND_FLAG  3
