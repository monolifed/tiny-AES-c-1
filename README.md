### Tiny AES in C

This is a small and portable implementation of the AES [ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29), [CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29) and [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) encryption algorithms written in C.

The API is very simple and looks like this (I am using C99 `<stdint.h>`-style annotated types):

```C
/* Set AES variant, init, ctr crypt and cleanup */
AES_ctx ctx;
// keylen is either 16, 24, or 32 and determines whether it is AES 128, 192 or 256 respectively
AES_ctx_init(&ctx, keylen, key, iv);
AES_CTR_xcrypt_buffer(&ctx, buf, length);
Some_Secure_Zero_Function(&ctx, sizeof(ctx));

/* Initialize context calling (iv can be NULL): */
void AES_ctx_init(AES_ctx *ctx, uint32_t keylen, const uint8_t *key, const uint8_t *iv);

/* ... or reset IV or key at some point: */
void AES_ctx_set_key(AES_ctx *ctx, uint32_t keylen, const uint8_t *key);
void AES_ctx_set_iv(AES_ctx *ctx, const uint8_t *iv);

/* Then start encrypting and decrypting with the functions below: */
void AES_ECB_encrypt(AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(AES_ctx* ctx, uint8_t* buf);

void AES_CBC_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, uint32_t length);
void AES_CBC_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, uint32_t length);

/* Same function for encrypting as for decrypting in CTR mode */
void AES_CTR_xcrypt_buffer(AES_ctx* ctx, uint8_t* buf, uint32_t length);
```

Note: 
 * No padding is provided so for CBC and ECB all buffers should be mutiples of 16 bytes. For padding [PKCS7](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7) is recommendable.
 * ECB mode is considered unsafe for most uses and is not implemented in streaming mode. If you need this mode, call the function for every block of 16 bytes you need encrypted. See [wikipedia's article on ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)) for more details.

C++ users should `#include` [aes.hpp](https://github.com/kokke/tiny-AES-c/blob/master/aes.hpp) instead of [aes.h](https://github.com/kokke/tiny-AES-c/blob/master/aes.h)

There is no built-in error checking or protection from out-of-bounds memory access errors as a result of malicious input.

All material in this repository is in the public domain.
