#ifndef ECDHE_H
#define ECDHE_H

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <jansson.h>
#include "../error/error.h"
#include "../crypto/b64url.h"
#include "../json.h"
#include "ecdhe_m.h"
#include "../models/models.h"

class ECDHE_M;


#define ECDHE_CURVE_NAME          NID_X9_62_prime256v1
#define ECDHE_EXCHANGE_ID_LEN     4
#define ECDHE_NONCE_LEN           8
#define ECDHE_SIGN_PARAM_LEN      32

int ecdhe_create_exchange_id(ECDHE_M *message);
int ecdhe_create_nonce(ECDHE_M *message);
int ecdhe_create_ephemeral_key(ECDHE_M *message);
int ecdhe_create_iv(ECDHE_M *message);
int ecdhe_create_encryption_key(ECDHE_M *message);
int ecdhe_create_session_key(ECDHE_M *message);

int ecdhe_encrypt_signature(ECDHE_M *message);
int ecdhe_decrypt_signature(ECDHE_M *message);
int ecdhe_derive_sha256(unsigned char *secret, unsigned char *info, int infoLen, unsigned char **res, int resLen);

int ecdhe_get_shared_key(EC_KEY *privKey, EC_POINT *pubKey, unsigned char **secret);
int ecdhe_get_public_key_from_json(json_t *json, EC_POINT **point);
int ecdhe_get_public_key_from_coordinates(unsigned char *x, unsigned char *y, EC_POINT **point);


#endif
