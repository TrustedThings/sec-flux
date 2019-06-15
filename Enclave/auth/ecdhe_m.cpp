#include "ecdhe_m.h"

ECDHE_M::ECDHE_M()
{
  error_init(&error);

  mExchangeId = NULL;
  mPeerExchangeId = NULL;
  mNonce = NULL;
  mAad = NULL;
  mCiphertext = NULL;
  mTag = NULL;
  mPrivKey = NULL;
  mKey = NULL;
  mIv = NULL;
  mEncryptionKey = NULL;
  mSessionKey = NULL;

  mMessage = NULL;
  mUnprotectedMessage = NULL;
  mSignature = NULL;
}

ECDHE_M::~ECDHE_M()
{
  /**
  if(mExchangeId == NULL) delete[] mExchangeId;
  if(mPeerExchangeId!= NULL) delete[] mPeerExchangeId;
  if(mNonce!= NULL) delete[] mNonce;
  if(mAad!= NULL) delete[] mAad;
  if(mCiphertext!= NULL) delete[] mCiphertext;
  if(mTag!= NULL) delete[] mTag;
  if(mPrivKey != NULL) EC_KEY_free(mPrivKey);
  if(mKey != NULL) delete[] mKey;
  if(mIv != NULL) delete[] mIv;
  if(mEncryptionKey != NULL) delete[] mEncryptionKey;
  if(mSessionKey != NULL) delete[] mSessionKey;

  if(mMessage != NULL) json_decref(mMessage);
  if(mUnprotectedMessage != NULL) json_decref(mUnprotectedMessage);
  if(mSignature != NULL) json_decref(mSignature);
**/
}


int ECDHE_M::set_exchange_id(unsigned char *exchangeId)
{
  mExchangeId = exchangeId;
  return 1;
}

int ECDHE_M::set_peer_exchange_id(unsigned char *peerExchangeId)
{
  mPeerExchangeId = peerExchangeId;
  return 1;
}

int ECDHE_M::set_nonce(unsigned char *nonce)
{
  mNonce = nonce;
  return 1;
}

int ECDHE_M::set_key(unsigned char *key)
{
  mKey = key;
  return 1;
}

int ECDHE_M::set_iv(unsigned char *iv)
{
  mIv = iv;
  return 1;
}

int ECDHE_M::set_ephemeral_key(EC_KEY *key)
{
  mPrivKey = key;
  return 1;
}

int ECDHE_M::set_aad(unsigned char *aad)
{
  mAad = aad;
  return 1;
}

int ECDHE_M::set_cipher(unsigned char *ciphertext, int len, unsigned char *tag)
{
  mCiphertext = ciphertext;
  mCiphertextLen = len;
  mTag = tag;
  return 1;
}

int ECDHE_M::set_signature(const BIGNUM *r, const BIGNUM *s)
{
  char *rB, *sB;
  rB = bn2b64url(r);
  sB = bn2b64url(s);
  mSignature = json_pack("{s:s,s:s}", "r", rB, "s", sB);
  free(rB);
  free(sB);
  return 1;
}

int ECDHE_M::set_json_signature(json_t **signature)
{
  mSignature = *signature;
}

int ECDHE_M::set_message(json_t **message)
{
  mMessage = *message;
}

int ECDHE_M::set_unprotected_message(json_t **message)
{
  mUnprotectedMessage = *message;
}

int ECDHE_M::set_encryption_key(unsigned char *key)
{
  mEncryptionKey = key;
  return 1;
}

int ECDHE_M::set_session_key(unsigned char *key)
{
  mSessionKey = key;
  return 1;
}

int ECDHE_M::get_exchange_id(unsigned char **exchangeId)
{
  *exchangeId = mExchangeId;
  return 1;
}

int ECDHE_M::get_unprotected_message(json_t **message)
{
  *message = mUnprotectedMessage;
  return 1;
}

int ECDHE_M::get_text_message(unsigned char **message, int *len)
{
  unsigned char *tmp = json_to_unsigned_char(mMessage, JSON_COMPACT);
  *len = strlen((const char *)tmp) + 1;
  *message = new unsigned char[*len];
  memcpy(*message, tmp, *len);
  delete[] tmp;
}

int ECDHE_M::get_text_message_len(int *len)
{
  unsigned char *tmp;
  get_text_message(&tmp, len);
  delete[] tmp;
  return 1;
}

int ECDHE_M::get_message(json_t **json)
{
  *json = mMessage;
  return 1;
}

int ECDHE_M::get_text_signature(unsigned char **signature, int *len)
{
  *signature = json_to_unsigned_char(mSignature, JSON_COMPACT);
  *len = strlen((const char *)*signature);
  return 1;
}

int ECDHE_M::get_json_signature(json_t **json)
{
  *json = mSignature;
  return 1;
}

int ECDHE_M::get_cipher(unsigned char **ciphertext, int *len, unsigned char **tag)
{
  *ciphertext = mCiphertext;
  *len = mCiphertextLen;
  *tag = mTag;
  return 1;
}

int ECDHE_M::get_ephemeral_key(EC_KEY **key)
{
  *key = mPrivKey;
  return 1;
}

int ECDHE_M::get_iv(unsigned char **iv)
{
  *iv = mIv;
  return 1;
}

int ECDHE_M::get_aad(unsigned char **aad)
{
  *aad = mAad;
  return 1;
}

int ECDHE_M::get_key(unsigned char **key)
{
  *key = mKey;
  return 1;
}

int ECDHE_M::get_encryption_key(unsigned char **key)
{
  *key = mEncryptionKey;
  return 1;
}

int ECDHE_M::get_session_key(unsigned char **key)
{
  *key = mSessionKey;
  return 1;
}

int ECDHE_M::json_add_exchange_id(json_t *json, const char *label)
{
  char *b64 = bin2b64url(mExchangeId, ECDHE_EXCHANGE_ID_LEN);
  json_t *str = json_string(b64);
  json_object_set_new(json, label, str);
  free(b64);
  return 1;
}



int ECDHE_M::json_add_peer_exchange_id(json_t *json, const char *label)
{
  char *b64 = bin2b64url(mPeerExchangeId, ECDHE_EXCHANGE_ID_LEN);
  json_t *str = json_string(b64);
  json_object_set_new(json, label, str);
  free(b64);
  return 1;
}

int ECDHE_M::json_add_nonce(json_t *json)
{
  char *b64 = bin2b64url(mNonce, ECDHE_NONCE_LEN);
  json_t *str = json_string(b64);
  json_object_set_new(json, "nonce", str);
  free(b64);
  return 1;
}

int ECDHE_M::json_add_pub_key(json_t *json, const char *label)
{
  const BIGNUM *x, *y;
  ec_coordinates_from_key(mPrivKey, &x, &y);
  //printf("x: %s\n", BN_bn2hex(x));
  //printf("y: %s\n\n", BN_bn2hex(y));
  char *xStr = bn2b64url(x);
  char *yStr = bn2b64url(y);

  json_t *pKey = json_pack(
      "{s:s,s:b,s:[s],s:s,s:s,s:s}", 
      "crv", "P-256",
      "ext", true,
      "key_ops", "verify",
      "kty", "EC",
      "x", xStr, 
      "y", yStr
  );
  free(xStr);
  free(yStr);
  json_object_set_new(json, label, pKey);
  return 0;
}

int ECDHE_M::json_add_cipher(json_t *json)
{
  json_t *ciphertext = json_string(bin2b64url(mCiphertext, mCiphertextLen));
  json_t *tag = json_string(bin2b64url(mTag, TAG_LEN));
  json_object_set_new(json, "ciphertext", ciphertext);
  json_object_set_new(json, "tag", tag);
  return 1;
}

void ECDHE_M::get_error()
{

}
