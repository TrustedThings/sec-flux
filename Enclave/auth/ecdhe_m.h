#ifndef ECDHE_M_H
#define ECDHE_M_H

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
#include "../crypto/crypto.h"
#include "../utils.h"
#include "../error/error.h"
#include "../json.h"
#include "../crypto/b64url.h"
#include "string.h"
#include "ecdhe.h"

class ECDHE_M
{
  public:
    ECDHE_M();
    ~ECDHE_M();


    int set_exchange_id(unsigned char *exchangeId);
    int set_peer_exchange_id(unsigned char *peerExchangeId);
    int set_nonce(unsigned char *nonce);
    int set_ephemeral_key(EC_KEY *key);
    int set_key(unsigned char *key);
    int set_iv(unsigned char *iv);
    int set_aad(unsigned char *aad);
    int set_signature(const BIGNUM *r, const BIGNUM *s);
    int set_json_signature(json_t **signature);
    int set_cipher(unsigned char *ciphertext, int len, unsigned char *tag);
    int set_message(json_t **message);
    int set_unprotected_message(json_t **message);
    int set_encryption_key(unsigned char *key);
    int set_session_key(unsigned char *key);

    int get_exchange_id(unsigned char **exchangeId);
    int get_unprotected_message(json_t **message);
    int get_text_message(unsigned char **message, int *len);
    int get_text_message_len(int *len);
    int get_message(json_t **json);
    int get_text_signature(unsigned char **signature, int *len);
    int get_json_signature(json_t **json);
    int get_cipher(unsigned char **ciphertext, int *len, unsigned char **tag);
    int get_ephemeral_key(EC_KEY **key);
    int get_iv(unsigned char **iv);
    int get_aad(unsigned char **aad);
    int get_key(unsigned char **key);
    int get_encryption_key(unsigned char **key);
    int get_session_key(unsigned char **key);

    int json_add_exchange_id(json_t *json, const char *label);
    int json_add_peer_exchange_id(json_t *json, const char *label);
    int json_add_nonce(json_t *json);
    int json_add_pub_key(json_t *json, const char *label);
    int json_add_cipher(json_t *json);

    void get_error();

  private:

    json_t *mMessage;
    json_t *mUnprotectedMessage;
    EC_KEY *mPrivKey;
    unsigned char *mExchangeId;
    unsigned char *mPeerExchangeId;
    unsigned char *mNonce;
    unsigned char *mAad;
    unsigned char *mCiphertext;
    int mCiphertextLen;
    unsigned char *mTag;
    unsigned char *mKey;
    unsigned char *mIv;
    unsigned char *mEncryptionKey;
    unsigned char *mSessionKey;
    json_t *mSignature;

    error_t error;

};

#endif
