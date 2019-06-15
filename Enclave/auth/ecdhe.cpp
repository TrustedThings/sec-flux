#include "ecdhe.h"

int ecdhe_encrypt_signature(ECDHE_M *message)
{
  error_t error;
  unsigned char *plaintext;
  int plaintextLen;
  message->get_text_signature(&plaintext, &plaintextLen);
  //printf("text signature: %s\n", plaintext);
  unsigned char *ciphertext = new unsigned char[plaintextLen];
  unsigned char *key;
  message->get_encryption_key(&key);
  unsigned char *tag = new unsigned char [TAG_LEN];
  unsigned char *aad;
  message->get_aad(&aad);
  unsigned char *iv;
  message->get_iv(&iv);
  aes_256_gcm_encrypt(plaintext, plaintextLen, ciphertext, key, iv, tag, aad, SHA256_DIGEST_LENGTH, &error);
  //printf("encrypted text: %s\n", bin2hex(ciphertext, plaintextLen));
  //printf("aad: %s\n", bin2hex(aad, SHA256_DIGEST_LENGTH));
  //printf("tag: %s\n", bin2hex(tag, TAG_LEN));
  //printf("key: %s\n", bin2hex(key, KEY_LEN));
  //printf("iv: %s\n", bin2hex(iv, IV_LEN));
  message->set_cipher(ciphertext, plaintextLen, tag);

  return 1;
}

int ecdhe_decrypt_signature(ECDHE_M *message)
{
  error_t error;
  unsigned char *ciphertext;
  unsigned char *tag;
  int len;
  message->get_cipher(&ciphertext, &len, &tag);
  unsigned char *aad;
  message->get_aad(&aad);
  unsigned char *key;
  message->get_encryption_key(&key);
  unsigned char *iv;
  message->get_iv(&iv);
  unsigned char *plaintext = new unsigned char[len];
  //printf("encrypted text: %s\n", bin2hex(ciphertext, len));
  //printf("aad: %s\n", bin2hex(aad, SHA256_DIGEST_LENGTH));
  //printf("tag: %s\n", bin2hex(tag, TAG_LEN));
  //printf("key: %s\n", bin2hex(key, KEY_LEN));
  //printf("iv: %s\n", bin2hex(iv, IV_LEN));
  aes_256_gcm_decrypt(ciphertext, len, plaintext, key, iv, tag, aad, SHA256_DIGEST_LENGTH, &error);
  //printf("plaintext: %s\n", plaintext);

  json_error_t jsonError;
  json_t *signature = json_loadb((const char *)plaintext, len, 0, &jsonError);
  message->set_json_signature(&signature);

}

int ecdhe_derive_sha256(unsigned char *secret, unsigned char *info, int infoLen, unsigned char **res, int resLen)
{
  //printf("\nKEY DERIVATION: \n");
  EVP_PKEY_CTX *ctx;
  // DEBUG
  unsigned char *infoStr = new unsigned char [infoLen + 1];
  memcpy(infoStr, info, infoLen);
  infoStr[infoLen] = '\0';
  //printf("info: %d, %s\n", infoLen, infoStr);
  //printf("secret: %s\n", bin2hex(secret, KEY_LEN));
  unsigned char *ret = new unsigned char[resLen];
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
  EVP_PKEY_derive_init(ctx);
  EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
  EVP_PKEY_CTX_set1_hkdf_salt(ctx, "", 0);
  EVP_PKEY_CTX_set1_hkdf_key(ctx, secret, KEY_LEN);
  EVP_PKEY_CTX_add1_hkdf_info(ctx, info, infoLen);
  size_t sLen = resLen;
  EVP_PKEY_derive(ctx, ret, &sLen);
  EVP_PKEY_CTX_free(ctx);
  //printf("ret: %zu, %s\n", sLen, bin2hex(ret, resLen));
  *res = ret;
  //printf("\n");
  return 1;
}


int ecdhe_create_session_key(ECDHE_M *message)
{
  unsigned char *key;
  unsigned char *secret;
  const char *prefix = "SESSION-KEY";
  int prefixLen = strlen(prefix);
  unsigned char *aad;
  message->get_aad(&aad);
  char *bAad = bin2b64url(aad, SHA256_DIGEST_LENGTH);
  int aadLen = strlen(bAad);
  message->get_key(&secret);
  int infoLen = prefixLen + aadLen;
  unsigned char *info = new unsigned char[infoLen];
  memcpy(info, prefix, prefixLen);
  memcpy(info + prefixLen, bAad, aadLen);
  ecdhe_derive_sha256(secret, info, infoLen, &key, KEY_LEN);
  //printf("KEY: %s\n", bin2hex(key, KEY_LEN));
  delete[] bAad;
  delete[] info;

  message->set_session_key(key);
}

int ecdhe_create_iv(ECDHE_M *message)
{
  unsigned char *iv;
  unsigned char *secret;
  const char *prefix = "IV-GENERATION";
  int prefixLen = strlen(prefix);
  unsigned char *aad;
  message->get_aad(&aad);
  char *bAad = bin2b64url(aad, SHA256_DIGEST_LENGTH);
  int bAadLen = strlen(bAad);
  message->get_key(&secret);
  int infoLen = prefixLen + bAadLen;
  unsigned char *info = new unsigned char[infoLen];
  memcpy(info, prefix, prefixLen);
  memcpy(info + prefixLen, bAad, bAadLen);
  ecdhe_derive_sha256(secret, info, infoLen, &iv, IV_LEN);
  //printf("IV: %s\n", bin2hex(iv, IV_LEN));

  delete[] bAad;
  delete[] info;

  message->set_iv(iv);
  return 1;
}

int ecdhe_create_encryption_key(ECDHE_M *message)
{
  unsigned char *key;
  unsigned char *secret;
  const char *prefix = "GCM256ENCRYPTION";
  int prefixLen = strlen(prefix);
  unsigned char *aad;
  message->get_aad(&aad);
  char *bAad = bin2b64url(aad, SHA256_DIGEST_LENGTH);
  int aadLen = strlen(bAad);
  message->get_key(&secret);
  int infoLen = prefixLen + aadLen;
  unsigned char *info = new unsigned char[infoLen];
  memcpy(info, prefix, prefixLen);
  memcpy(info + prefixLen, bAad, aadLen);
  ecdhe_derive_sha256(secret, info, infoLen, &key, KEY_LEN);
  //printf("KEY: %s\n", bin2hex(key, KEY_LEN));
  delete[] bAad;
  delete[] info;

  message->set_encryption_key(key);
}

int ecdhe_get_shared_key(EC_KEY *privKey, EC_POINT *pubKey, unsigned char **secret)
{
  int len = KEY_LEN;
  *secret = new unsigned char[KEY_LEN];
  ECDH_compute_key(*secret, len, pubKey, privKey, NULL);
  return 1;
}

int ecdhe_check_message_1(json_t *message)
{
  //TODO: complete
  return 1;
}


int ecdhe_create_exchange_id(ECDHE_M *message)
{
  unsigned char *exchangeId = new unsigned char[ECDHE_EXCHANGE_ID_LEN];
  int ret = RAND_bytes(exchangeId, ECDHE_EXCHANGE_ID_LEN);
  //printf("exchange id: %s\n", bin2hex(exchangeId, ECDHE_EXCHANGE_ID_LEN));
  message->set_exchange_id(exchangeId);
  return 1;
}

int ecdhe_create_nonce(ECDHE_M *message)
{
  unsigned char *nonce = new unsigned char[ECDHE_NONCE_LEN];
  RAND_bytes(nonce, ECDHE_NONCE_LEN);
  message->set_nonce(nonce);
  return 1;
}

int ecdhe_create_ephemeral_key(ECDHE_M *message)
{
  EC_KEY *key = EC_KEY_new_by_curve_name(ECDHE_CURVE_NAME);
  EC_KEY_generate_key(key);
  message->set_ephemeral_key(key);
  //printf("\npriv key: %s\n", BN_bn2hex(EC_KEY_get0_private_key(key)));

  return 1;
}

int ecdhe_get_public_key_from_json(json_t *json, EC_POINT **point)
{
  BN_CTX *ctx = BN_CTX_new();
  EC_KEY *key = EC_KEY_new_by_curve_name(ECDHE_CURVE_NAME);
  const EC_GROUP *group = EC_KEY_get0_group(key);
  *point = EC_POINT_new(group);
  BIGNUM *x = b64url2bn((unsigned char *)json_string_value(json_object_get(json, "x")));
  BIGNUM *y = b64url2bn((unsigned char *)json_string_value(json_object_get(json, "y")));
  EC_POINT_set_affine_coordinates_GFp(group, *point, x, y, ctx);


  BN_free(x);
  BN_free(y);
  //EC_GROUP_free(group);
  EC_KEY_free(key);
  BN_CTX_free(ctx);
  return 1;
}

int ecdhe_get_public_key_from_coordinates(unsigned char *x, unsigned char *y, EC_POINT **point)
{
  BN_CTX *ctx = BN_CTX_new();
  EC_KEY *key = EC_KEY_new_by_curve_name(ECDHE_CURVE_NAME);
  const EC_GROUP *group = EC_KEY_get0_group(key);
  *point = EC_POINT_new(group);
  BIGNUM *bx = BN_bin2bn(x, KEY_LEN, NULL);
  BIGNUM *by = BN_bin2bn(y, KEY_LEN, NULL);
  EC_POINT_set_affine_coordinates_GFp(group, *point, bx, by, ctx);


  BN_free(bx);
  BN_free(by);
  //EC_GROUP_free(group);
  EC_KEY_free(key);
  BN_CTX_free(ctx);
  return 1;
}
