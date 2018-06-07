#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

#define AES_BLOCKLEN 16 //AES has 128-bit block length

#define AES128_ID 0
#define AES192_ID 1
#define AES256_ID 2


#define AES128_KEYLEN 16
#define AES192_KEYLEN 24
#define AES256_KEYLEN 32

// AESxxx_KEYLEN / 4 + 6
// #define AES128_NR 10
// #define AES192_NR 12
// #define AES256_NR 14

// AES_BLOCKLEN * (AESxxx_NR + 1)
// #define AES128_KEYEXPSIZE 176
// #define AES192_KEYEXPSIZE 208
// #define AES256_KEYEXPSIZE 240

// enough to keep RoundKey of all variants
#define AES_KEYEXPSIZE 240


typedef struct aes_ctx_t
{
	uint8_t flags;
	//state_t state;
	uint8_t Iv[AES_BLOCKLEN];
	// buffer used in CTR and CBC decrypt
	uint8_t buffer[AES_BLOCKLEN];
	uint8_t RoundKey[AES_KEYEXPSIZE];
} AES_ctx;

typedef enum
{
	AES_128 = 0x0,
	AES_192 = 0x1,
	AES_256 = 0x2,
	AES_type_mask = 0x3,
	AES_has_key = 0x04,
	AES_has_iv = 0x08,
	AES_crypt = 0x10,
} AES_flags;

void AES_ctx_init(AES_ctx *ctx, uint32_t keylen, const uint8_t *key, const uint8_t *iv);
void AES_ctx_set_key(AES_ctx *ctx, uint32_t keylen, const uint8_t *key);
void AES_ctx_set_iv(AES_ctx *ctx, const uint8_t *iv);

// buffer size is exactly AES_BLOCKLEN bytes;
// you need only AES_init_ctx as IV is not used in ECB
// NB: ECB is considered insecure for most uses
void AES_ECB_encrypt(AES_ctx *ctx, uint8_t *buf);
void AES_ECB_decrypt(AES_ctx *ctx, uint8_t *buf);

// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key
void AES_CBC_encrypt_buffer(AES_ctx *ctx, uint8_t *buf, uint32_t length);
void AES_CBC_decrypt_buffer(AES_ctx *ctx, uint8_t *buf, uint32_t length);

// Same function for encrypting as for decrypting.
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx with AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key
void AES_CTR_xcrypt_buffer(AES_ctx *ctx, uint8_t *buf, uint32_t length);

#endif //_AES_H_
