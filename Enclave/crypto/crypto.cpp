
#include "crypto.h"
#include "../utils.h"
#include "string.h"
#include "b64url.h"


unsigned char *bin2hex(unsigned char *bin, int len)
{
  BIGNUM *bn = BN_new();
  unsigned char *tmp;
  unsigned char *hexadecimal = new unsigned char[2 * len + 1];
  memset(hexadecimal, '0', 2 * len);
  hexadecimal[2 * len] = '\0';
  bn = BN_bin2bn(bin, len, bn);
  tmp = (unsigned char *)BN_bn2hex(bn);
  int tmpLen = strlen((const char *)tmp);
  memcpy(hexadecimal +  2 * len - tmpLen, tmp, tmpLen);
  BN_free(bn);
  OPENSSL_free(tmp);
  return hexadecimal;
}

unsigned char *hex2bin(const char *hex)
{
  BIGNUM *bn = BN_new();
  unsigned char *binary = new unsigned char[strlen(hex) / 2];
  BN_hex2bn(&bn, hex);
  BN_bn2bin(bn, binary);
  BN_free(bn);
  return binary;
}

int aes_256_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
  unsigned char *ciphertext, unsigned char *key,
  unsigned char *iv, unsigned char *tag,
  unsigned char *aad, int aad_len, error_t *error)
{
  int len;

  EVP_CIPHER_CTX *ctx;
  // Initialise context
  ctx = EVP_CIPHER_CTX_new();
  // Initialise encryption operation
  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
  // Initialise key and iv
  EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
  // Provide aad
  if(aad_len > 0){
    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);
  }
  // Encrypt message
  EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
  // Finalise the encryption
  EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  // Get the tag
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
  // Clean up
  EVP_CIPHER_CTX_free(ctx);
  return 1;
}

int aes_256_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
  unsigned char *plaintext, unsigned char *key,
  unsigned char *iv, unsigned char *tag,
  unsigned char *aad, int aad_len, error_t *error)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ret;
  // Create context
  ctx = EVP_CIPHER_CTX_new();
  // Initialise decryption operation
  ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
  //printf("%d\n", ret);
  // Initialise key and iv
  ret = EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
  //printf("%d\n", ret);
  //printf("key iv: %d\n", ret);
  // Provide aad
  //printf("aad_len: %d\n", aad_len);
  if(aad_len > 0){
    ret = EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);
    //printf("aad: %d\n", ret);
  }
  // Decrypt message
  ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
  //printf("dec: %d\n", ret);
  //printf("%d\n", ret);
  // Set tag value
  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
  //printf("tag: %d\n", ret);
  //printf("%d\n", ret);
  //Finalise and check decryption
  ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  //printf("fin: %d\n", ret);
  //printf("%d\n", ret);
  // Clean up
  EVP_CIPHER_CTX_free(ctx);
  if(ret > 0){
    return 1;
  } else{
    return 0;
  }
}

int ec_key_from_hex_private_key(EC_KEY **key, const char *hex_priv, error_t *error)
{
  /**
  if(hex_priv == NULL || strlen(hex_priv) != 56){
    printf("null!\n");
    return 0;
  }**/
  BIGNUM *bn = BN_new();
  BN_CTX *bn_ctx = BN_CTX_new();
  EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_POINT *ec_point = EC_POINT_new(ec_group);

  BN_hex2bn(&bn, hex_priv);
  EC_POINT_mul(ec_group, ec_point, bn, NULL, NULL, bn_ctx);
  EC_KEY_set_private_key(ec_key, bn);
  EC_KEY_set_public_key(ec_key, ec_point);

  *key = ec_key;
  BN_free(bn);
  BN_CTX_free(bn_ctx);
  EC_GROUP_free(ec_group);
  EC_POINT_free(ec_point);
  return 1;
}

char *bin2b64url(unsigned char *bin, int len)
{
  return b64url_encode(bin, len);
}

char *bn2b64url(const BIGNUM *bn)
{
  unsigned char *tmp = new unsigned char[BN_num_bytes(bn)];
  BN_bn2bin(bn, tmp);
  char *val = b64url_encode(tmp, BN_num_bytes(bn));
  delete[] tmp;
  return val;
}

BIGNUM *b64url2bn(unsigned char *from)
{
  return b64url2bn(from, strlen((const char *)from));
}

BIGNUM *b64url2bn(unsigned char *from, int len)
{
  size_t size;
  unsigned char *tmp = b64url_decode_ex((const char *)from, len, &size);
  BIGNUM *bn = BN_bin2bn(tmp, size, NULL);
  //printf("in function: %s\n", BN_bn2hex(bn));
  return bn;
}

char *hex2b64url(const char *hex)
{
  unsigned char *bin = hex2bin(hex);
  char *b64url = b64url_encode(bin, strlen(hex) / 2);
  delete[] bin;
  return b64url;
}

unsigned char *b64url2hex(char *b64url)
{
  size_t size;
  int len = strlen((const char *)b64url);
  unsigned char *bin = b64url_decode_ex((const char *)b64url, len, &size);
  unsigned char *hex = bin2hex(bin, size);
  delete[] bin;
  return hex;
}

unsigned char *b64url2bin(char *b64url, int *len)
{
  size_t tmp;
  int size = strlen((const char *)b64url);
  unsigned char *bin = b64url_decode_ex(b64url, size, &tmp);
  *len = (int)tmp;
  return bin;

}

int ec_coordinates_from_key(EC_KEY *key, const BIGNUM **x, const BIGNUM **y)
{
  const EC_POINT *point;
  const EC_GROUP *group;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *xt = BN_new();
  BIGNUM *yt = BN_new();
  point = EC_KEY_get0_public_key(key);
  if(point == NULL) {printf("point null\n");}
  group = EC_KEY_get0_group(key);
  if(group == NULL) {printf("group null\n");}
  if(ctx == NULL) {printf("context null\n");}
  EC_POINT_get_affine_coordinates_GFp(group, point, xt, yt, ctx);

  *x = xt;
  *y = yt;
  BN_CTX_free(ctx);
  return 1;
}

int ec_key_from_hex_public_coordinates(EC_KEY **key, const char *pub_x_hex, const char *pub_y_hex)
{
  /**
  if(hex_pub == NULL || strlen(hex_pub) != 114){
    return 0;
  }**/
  //printf("loL\n");
  BN_CTX *bn_ctx = BN_CTX_new();
  EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  EC_POINT *ec_point = EC_POINT_new(ec_group);
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  int ret = BN_hex2bn(&x, pub_x_hex);
  BN_hex2bn(&y, pub_y_hex);

  EC_POINT_set_affine_coordinates_GFp(ec_group, ec_point, x, y, bn_ctx);
  //ec_point = EC_POINT_hex2point(ec_group, hex_pub, ec_point, bn_ctx);
  EC_KEY_set_public_key(ec_key, ec_point);

  *key = ec_key;

  BN_CTX_free(bn_ctx);
  EC_GROUP_free(ec_group);
  EC_POINT_free(ec_point);
  BN_free(x);
  BN_free(y);
  return 1;
}


void sig2bn(ECDSA_SIG *sig, BIGNUM **r, BIGNUM **s)
{
    int sigSize = i2d_ECDSA_SIG(sig, NULL);
    unsigned char *sigBytes = new unsigned char[sigSize];
    unsigned char *p;
    p = sigBytes;
    i2d_ECDSA_SIG(sig, &p);
    int d = 0;
    if(sigBytes[sigSize - 32] >= 128) d = 1;
    *r = BN_bin2bn(sigBytes + sigSize - 66 - d, 32, NULL);
    *s = BN_bin2bn(sigBytes + sigSize - 32, 32, NULL);
    delete[] sigBytes;
    return;
}

ECDSA_SIG *bn2sig(BIGNUM *r, BIGNUM *s)
{
    unsigned char *rBytes = new unsigned char[32];
    unsigned char *sBytes = new unsigned char[32];
    BN_bn2bin(r, rBytes);
    BN_bn2bin(s, sBytes);
    int rA = 0;
    int sA = 0;
    if(rBytes[0] >= 128) rA = 1;
    if(sBytes[0] >= 128) sA = 1;
    int sigSize = 2 * (32 + 2) + 2 + rA + sA;
    unsigned char *sigBytes = new unsigned char[sigSize];
    // Build structure
    sigBytes[0] = 0x30;
    sigBytes[1] = 2 * (32 + 2) + rA + sA;
    // r
    sigBytes[2] = 0x02;
    sigBytes[3] = 32 + rA;
    sigBytes[4] = 0x00;
    memcpy(sigBytes + 4 + rA, rBytes, 32);
    // s
    sigBytes[4 + rA + 32] = 0x02;
    sigBytes[4 + rA + 32 + 1] = 32 + sA;
    sigBytes[4 + rA + 32 + 2] = 0x00;
    memcpy(sigBytes + 4 + rA + 32 + 2 + sA, sBytes, 32);
    
    unsigned char *p;
    p = sigBytes;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&p, sigSize);
    delete[] rBytes;
    delete[] sBytes;
    delete[] sigBytes;
    return sig;
}


