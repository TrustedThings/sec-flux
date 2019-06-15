#ifndef CRYPTO_H
#define CRYPTO_H

#include "../error/error.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define KEY_LEN 32
#define IV_LEN 12
#define TAG_LEN 16
#define PUB_KEY_LEN 57
#define PRI_KEY_LEN 28
#define PUB_KEY_COORD_LEN 32


unsigned char *bin2hex(unsigned char *bin, int len);
unsigned char *hex2bin(const char *hex);

int aes_256_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
  unsigned char *ciphertext, unsigned char *key,
  unsigned char *iv, unsigned char *tag,
  unsigned char *aad, int aad_len, error_t *error);

int aes_256_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
  unsigned char *plaintext, unsigned char *key,
  unsigned char *iv, unsigned char *tag,
  unsigned char *aad, int aad_len, error_t *error);

int ec_coordinates_from_key(EC_KEY *key, const BIGNUM **x, const BIGNUM **y);
char *bin2b64url(unsigned char *bin, int len);
char *bn2b64url(const BIGNUM *bn);
char *hex2b64url(const char *hex);
unsigned char *b64url2hex(char *b64url);
unsigned char *b64url2bin(char *b64url, int *len);
BIGNUM *b64url2bn(unsigned char *from);
BIGNUM *b64url2bn(unsigned char *from, int len);

int ec_key_from_hex_private_key(EC_KEY **key, const char *hex_priv, error_t *error);
int ec_key_from_hex_public_coordinates(EC_KEY **key, const char *pub_x_hex, const char *pub_y_hex);

void sig2bn(ECDSA_SIG *sig, BIGNUM **r, BIGNUM **s);
ECDSA_SIG *bn2sig(BIGNUM *r, BIGNUM *s);

#endif
