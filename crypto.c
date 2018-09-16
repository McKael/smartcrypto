#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <arpa/inet.h>

#include "aes.h"
#include "keys.h"
#include "crypto.h"

/*
void bufToHex(unsigned char *buf, char *out, int len, int doBig)
{
	char tmpBuf[0x10];
	if(doBig)
		sprintf(out,"%02X",buf[0]);
	else
		sprintf(out,"%02x",buf[0]);
	for(int i=1; i< len ; i++)
	{
		if(doBig)
			sprintf(tmpBuf,"%02X",buf[i]);
		else
			sprintf(tmpBuf,"%02x",buf[i]);
		strcat(out,tmpBuf);
	}
}
unsigned char *HexToBuf(const char *hex)
{
	int hexLen = strlen(hex);
	unsigned char *bytearray = malloc(hexLen+10);
	for (int i = 0; i < (hexLen / 2); i++)
	{
		sscanf(hex + 2*i, "%02x", (unsigned int*)&bytearray[i]);
		//printf("bytearray %02x\n", bytearray[i]);
	}
	return bytearray;
}
void printBuffer(char *label, unsigned char *buf, int bufSize)
{
	printf("%s: ", label);
	for(int i =0; i< bufSize; i++)
	{
		printf("%02x",buf[i]);
	}
	puts("");
}
*/
int EncryptParameterDataWithAES(unsigned char *pIn, unsigned char *pOut)
{
	unsigned int num;
	unsigned char iv[0x10];
	for (num = 0u; num < 128u; num += 16u)
	{
		memset(iv, 0, 16);
		AES_128_CBC_Enc(pIn + num, pOut + num, wbKey, iv, 16);
	}
	return 0;
}
int DecryptParameterDataWithAES(unsigned char *pIn, unsigned char *pOut)
{
	unsigned int num;
	unsigned char iv[0x10];
	for (num = 0u; num < 128u; num += 16u)
	{
		memset(iv, 0, 16);
		AES_128_CBC_Dec(pIn + num, pOut + num, wbKey, iv, 16);
	}
	return 0;
}
void applySamyGOKeyTransform(unsigned char *pIn, unsigned char *pOut)
{
	AES_128_Transform(3,transKey,pIn,pOut);
}

// Write the AES key, the digest hash as binary bytes and the hello as hex
// strings.  len is the maximum size for the hello string.
// The pointers for the AES key and the hash should be large enough:
// - aes_key is 16 bytes long
// - hash is 20 bytes long
int generateServerHello(const char *userId, const char *pin,
		char *hello_out, size_t len,
		char *aes_key_out, char *hash_out)
{
	int dataLen;
	unsigned char data[256];
	unsigned char iv[0x10];
	unsigned char hash[SHA_DIGEST_LENGTH];
	unsigned char swapped[256];
	unsigned char encrypted[256];
	//char dataText[2048];
	//char hashText[256];

	SHA1((unsigned char*)pin, strlen((char*)pin), hash);
	memcpy(aes_key_out, hash, 16);

	/*
	bufToHex(hash,(char*)hashText, 16,0);
	printf("AES key: %s\n",hashText);
	*/

	memset(iv, 0, 16);
	AES_128_CBC_Enc(publicKey, encrypted, hash, iv, 128);

	/*
	bufToHex(encrypted,(char*)hashText, 128,0);
	printf("AES encrypted: %s\n",hashText);
	*/

	EncryptParameterDataWithAES(encrypted,swapped);

	/*
	bufToHex(swapped,(char*)hashText, 128,0);
	printf("AES swapped: %s\n",hashText);
	*/

	dataLen=0;
	memset(data,0,sizeof(data));
	data[3]=strlen(userId);
	dataLen+=4;
	strcpy((char*)data+dataLen,userId);
	dataLen+=strlen(userId);
	memcpy(data+dataLen,swapped,128);
	dataLen+=128;
	/*
	bufToHex(data,dataText, dataLen,1);
	//printf("data buffer: %s\n",dataText);
	*/

	SHA1(data, dataLen, hash);
	/*
	bufToHex(hash,(char*)hashText, SHA_DIGEST_LENGTH,0);
	printf("hash: %s\n",hashText);
	*/

	memcpy(hash_out, hash, SHA_DIGEST_LENGTH);

	if (16+dataLen > len) {
		// The output hello string doesn't fit
		return -1;
	}

	const char header[] = {
		0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	memcpy(hello_out, header, sizeof(header));
	int pos = sizeof(header);
	hello_out[pos++] = 132+strlen(userId);
	memcpy(&hello_out[pos], data, dataLen);
	pos += dataLen;
	memset(&hello_out[pos], 0, 5);
	pos += 5;

	//printf("ServerHello: 01020000000000000000%02lX%s0000000000\n",
	//       132+strlen(userId), dataText);
        return pos;
}

#define GX_SIZE 0x80
#define USER_ID_POS 15
// Parses the ClientHello message
// All parameters but the gUserId are raw bytes.
// Returns 0 if the client hello is parsed successfully;
// Writes the SKPrime and ctx to the *_out variables.
// The pointers should be large enough:
// - SKPrime is 20 bytes long
// - ctx is 16 bytes long
int parseClientHello(const char *clientHello, unsigned int clientHelloSize,
		const char *hash, const char *aesKey, const char *gUserId,
		char *skprime_out, char *ctx_out)
{
	unsigned char hash2[SHA_DIGEST_LENGTH], hash3[SHA_DIGEST_LENGTH];
	// unsigned char dest_hash[SHA_DIGEST_LENGTH];
	unsigned char SKPrime[SHA_DIGEST_LENGTH+1], SKPrimeHash[SHA_DIGEST_LENGTH];
	//unsigned char *dest;
	unsigned char *userId,pEncWBGx[GX_SIZE], pEncGx[GX_SIZE], *finalBuffer;
	unsigned char iv[0x10],pGx[GX_SIZE],secretBytes[256], secretLen,thirdHashBuf[512];
	unsigned int *l,/*firstLen,*/userIdLen,/*thirdLen,destLen,*/ flagPos,finalPos;
	unsigned int gUserIdLen;

	gUserIdLen = strlen(gUserId);

	// Check clientHelloSize looks large enough
	if (clientHelloSize < gUserIdLen + USER_ID_POS + GX_SIZE + SHA_DIGEST_LENGTH + 2) {
		return ERR_SC_BAD_CLIENTHELLO; // Client Hello looks too small
	}

	/*l=(unsigned int*)&clientHello[7];
	firstLen = htonl(*l);*/
	l=(unsigned int*)&clientHello[11];
	userIdLen = htonl(*l);

	if (userIdLen != gUserIdLen) {
		return ERR_SC_BAD_USERID; // User IDs do not match
	}

	/*
	destLen = userIdLen + 132 + SHA_DIGEST_LENGTH;
	dest=malloc(destLen);
	thirdLen = userIdLen + 132;
	memcpy(dest,clientHello+11,thirdLen);
	memcpy(dest+thirdLen,hash,SHA_DIGEST_LENGTH);
	*/

	/*
	printf("\ndest: ");
	for(int i =0; i< destLen; i++)
	{
		printf("%02x",dest[i]);
	}
	*/

	userId=malloc(userIdLen+1);
	memcpy(userId,clientHello+USER_ID_POS,userIdLen);
	userId[userIdLen]=0;
	//printf("\nuserId: %s\n",userId);

	if (strcmp((const char *)userId, gUserId)) {
		return ERR_SC_BAD_USERID; // User IDs do not match
	}

	memcpy(pEncWBGx,clientHello+USER_ID_POS+userIdLen,GX_SIZE);
	/*
	printf("\npEncWBGx: ");
	for(int i =0; i< GX_SIZE; i++)
	{
		printf("%02x",pEncWBGx[i]);
	}
	*/

	DecryptParameterDataWithAES(pEncWBGx,pEncGx);

	/*
	printf("\npEncGx: ");
	for(int i =0; i< GX_SIZE; i++)
	{
		printf("%02x",pEncGx[i]);
	}
	*/

	memset(iv, 0, 16);
	AES_128_CBC_Dec(pEncGx, pGx, (const unsigned char*)aesKey, iv, GX_SIZE);

	/*
	printf("\npGx: ");
	for(int i =0; i< GX_SIZE; i++)
	{
		printf("%02x",pGx[i]);
	}
	puts("");
	*/

	BIGNUM *bn_prime, *bn_pGx, /**bn_publicKey,*/ *bn_privateKey, *bn_secret;
	BN_CTX *ctx; /* used internally by the bignum lib */

	ctx = BN_CTX_new();
	bn_secret = BN_new();
	bn_prime = BN_bin2bn(prime,sizeof(prime),NULL);
	bn_pGx= BN_bin2bn(pGx,GX_SIZE,NULL);
	/*bn_publicKey =*/ BN_bin2bn(publicKey,GX_SIZE,NULL);
	bn_privateKey = BN_bin2bn(privateKey,GX_SIZE,NULL);
	BN_mod_exp(bn_secret, bn_pGx, bn_privateKey, bn_prime,ctx);
	//printf("Secret: %s\n",BN_bn2hex(bn_secret));
	secretLen=BN_bn2bin(bn_secret,secretBytes);
	//printBuffer("secret",secretBytes,secretLen);

	memcpy(hash2,clientHello+USER_ID_POS+userIdLen+GX_SIZE,SHA_DIGEST_LENGTH);
	//printBuffer("hash2",hash2,SHA_DIGEST_LENGTH);

	memcpy(thirdHashBuf, userId,strlen((char*)userId));
	memcpy(thirdHashBuf+strlen((char*)userId), secretBytes, secretLen);
	//printBuffer("secret2",thirdHashBuf,secretLen+strlen((char*)userId));

	SHA1(thirdHashBuf, secretLen+strlen((char*)userId), hash3);
	//printBuffer("hash3",hash3,SHA_DIGEST_LENGTH);
	if (memcmp(hash2,hash3,SHA_DIGEST_LENGTH)) {
		return ERR_SC_PIN; // Pin error
	}
	// Pin OK :)

	flagPos = strlen((char*)userId) + USER_ID_POS + GX_SIZE + SHA_DIGEST_LENGTH;
	if (clientHello[flagPos]) {
		return ERR_SC_FIRST_FLAG;   // First flag error
	}
	l=(unsigned int*)&clientHello[flagPos+1];
	if (htonl(*l)) {
		return ERR_SC_SECOND_FLAG;  // Second flag error
	}

	/*
	SHA1(dest, destLen, dest_hash);
	//printBuffer("dest_hash",dest_hash,SHA_DIGEST_LENGTH);
	*/

	finalBuffer = malloc(userIdLen+ strlen((char*)userId)+ 384);
	finalPos=0;
	strcpy((char*)&finalBuffer[finalPos],(char*)userId);
	finalPos+=strlen((char*)userId);
	strcpy((char*)&finalBuffer[finalPos],(char*)gUserId);
	finalPos+=strlen((char*)gUserId);
	memcpy(&finalBuffer[finalPos],pGx,sizeof(pGx));
	finalPos+=sizeof(pGx);
	memcpy(&finalBuffer[finalPos],publicKey,sizeof(publicKey));
	finalPos+=sizeof(publicKey);
	memcpy(&finalBuffer[finalPos],secretBytes,secretLen);
	finalPos+=secretLen;

	SHA1(finalBuffer, finalPos, SKPrime);
	SKPrime[SHA_DIGEST_LENGTH]=0;
	//printBuffer("SKPrime",SKPrime,SHA_DIGEST_LENGTH);

	SHA1(SKPrime, SHA_DIGEST_LENGTH+1, SKPrimeHash);
	//printBuffer("SKPrimeHash",SKPrimeHash,SHA_DIGEST_LENGTH);
	applySamyGOKeyTransform(SKPrimeHash,SKPrimeHash);
	//printBuffer("ctx",SKPrimeHash,16);

	//bufToHex(SKPrime,(char*)out, SHA_DIGEST_LENGTH,0);
	//strncpy(skprime_out, out, SHA_DIGEST_LENGTH*2);
	//skprime_out[SHA_DIGEST_LENGTH*2] = 0;
	memcpy(skprime_out, SKPrime, SHA_DIGEST_LENGTH);

	//bufToHex(SKPrimeHash,(char*)out, 16,0);
	//strncpy(ctx_out, out, 16*2);
	//ctx_out[16*2] = 0;
	memcpy(ctx_out, SKPrimeHash, SHA_DIGEST_LENGTH);

	free(userId);
	free(finalBuffer);

	return 0;
}
