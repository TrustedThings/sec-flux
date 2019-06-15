#include "auth_manager.h"
#include "../models/client.h"
#include <jansson.h>
#include "../utils.h"
#include "exchange.h"
#include "ecdhe.h"
#include "ecdhe_m.h"
#include <openssl/rand.h>
#include "../crypto/crypto.h"

AuthManager::AuthManager()
{
    mMessage = NULL;
    // Debug
    mMainKey = NULL;
    mLastSessionId = 0;
}

AuthManager::~AuthManager()
{
    if(mMessage != NULL) delete mMessage;
    // Debug
    //if(mMainKey != NULL) EC_KEY_free(mMainKey);
}

int AuthManager::init(sqlite3 **db)
{
    mDb = db;
    error_t error;
    mInterceptor.init(mDb);
    // DEBUG, do not store private key like this
    int ret = ec_key_from_hex_private_key(&mMainKey, "B5E1CFEB2CB0D28DC1D12AE515BBEA4D4D0AAEE07CFEDC51A4EA1AEB08ED9D00", &error);

    // DEBUG
    /**
    BN_CTX *ctx = BN_CTX_new();
    //printf("ret: %d\n", ret);
    const EC_POINT *point = EC_KEY_get0_public_key(mMainKey);
    const EC_GROUP *group = EC_KEY_get0_group(mMainKey);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    ret = EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx);
    //printf("ret: %d\n", ret);
    //printf("x: %s, y: %s\n", BN_bn2hex(x), BN_bn2hex(y));
    **/
   
    return 1;
}

int AuthManager::get_message(char **message)
{
    if(mMessage == NULL) return -1;
    int len;
    mMessage->get_text_message((unsigned char **)message, &len);
    delete mMessage;
    mMessage = NULL;
}

int AuthManager::step1(const char *message1, int clientId, int *message2_len)
{
    if(mMessage != NULL) delete mMessage;
    mMessage = NULL;
    int ret;
    // Check message 1 
    ret = check_message_1(message1, clientId);
    if(ret != 1){
        print_error();
        return 0;
    }    

    // Create message 2
    ret = create_message_2(clientId, message2_len);

    return 1;
}

int AuthManager::step2(const char *message3, int clientId, int *message4_len)
{
    if(mMessage != NULL) delete mMessage;
    mMessage = NULL;
    int ret;
    // Check message 3
    ret = check_message_3(message3, clientId);

    ret = create_message_4(clientId, message4_len);

}

int AuthManager::check_message_1(const char *message1, int clientId)
{
    int ret;
    json_auto_t *json;
    json_error_t jsonError;
    int cid;

    // Check message format
    const char *exchangeIdb64, *nonceb64, *crv, *kty, *xb64, *yb64;
    bool ext;
    //printf("request: %s\n", message1);
    json = json_loads(message1, 0, &jsonError);
    if(json == NULL) return err("no valid json", error_misc);
    ret = json_unpack_ex(
        json, &jsonError, JSON_STRICT, 
        "{s:s,s:s,s:{s:s,s:b,s:[*],s:s,s:s,s:s}}", 
        "clientExchangeId", &exchangeIdb64, 
        "nonce", &nonceb64, 
        "clientPubKey", 
            "crv", &crv,
            "ext", &ext,
            "key_ops", 
            "kty", &kty,
            "x", &xb64, 
            "y", &yb64
    );
    if(ret != 0) return err("malformed json", error_misc);
    
    // TODO: Check fields lengths

    // Check client exists and is active
    MClient *client = new MClient(mDb);
    client->set_id(clientId);
    ret = client->get_by_id();

    if(ret == 0){
        return err("client not found", error_misc);
    }
    if(!client->get_is_active()){
        return err("client not active", error_misc);
    }
    delete client;

    // Register step
    mExchanges[cid] = {};
    int len;
    unsigned char *exchangeId = b64url2bin((char *)exchangeIdb64, &len);
    memcpy(mExchanges[clientId].clientExchangeId, exchangeId, ECDHE_EXCHANGE_ID_LEN);
    memcpy(mExchanges[clientId].message1, message1, strlen(message1) + 1);
    free(exchangeId);
    if(len != ECDHE_EXCHANGE_ID_LEN) return err("exchange id has wrong length", error_misc);

    // Register and check key
    unsigned char *x = b64url2bin((char *)xb64, &len);
    memcpy(mExchanges[clientId].clientPubKeyX, x, KEY_LEN);
    free(x);
    if(len != KEY_LEN) return err("key has wrong length", error_misc);
    unsigned char *y = b64url2bin((char *)yb64, &len);
    memcpy(mExchanges[clientId].clientPubKeyY, y, KEY_LEN);
    free(y);
    if(len != KEY_LEN) return err("key has wrong length", error_misc);

    return 1;
}

int AuthManager::create_message_2(int clientId, int *message2_len)
{
    if(mMessage != NULL) delete mMessage;
    mMessage = new ECDHE_M();

    // Create unprotected part of the message
    ecdhe_create_exchange_id(mMessage);
    unsigned char *eid;
    mMessage->get_exchange_id(&eid);
    memcpy(mExchanges[clientId].serverExchangeId, eid, ECDHE_EXCHANGE_ID_LEN);
    //printf("TEST EID: %d\n", mExchanges[clientId].serverExchangeId);
    ecdhe_create_nonce(mMessage);
    ecdhe_create_ephemeral_key(mMessage);
    EC_KEY *ephKey;
    mMessage->get_ephemeral_key(&ephKey);
    BN_bn2bin(EC_KEY_get0_private_key(ephKey), mExchanges[clientId].serverPrivateKey);
    mMessage->set_peer_exchange_id(mExchanges[clientId].clientExchangeId);

    // Create unprotected json header
    json_t *upJson = json_object();
    mMessage->json_add_peer_exchange_id(upJson, "clientExchangeId");
    mMessage->json_add_exchange_id(upJson, "serverExchangeId");
    mMessage->json_add_nonce(upJson);
    mMessage->json_add_pub_key(upJson, "serverPubKey");
    mMessage->set_unprotected_message(&upJson);

    // Compute shared key
    unsigned char *sharedKey;
    EC_POINT *pubKey;
    ecdhe_get_public_key_from_coordinates(
        mExchanges[clientId].clientPubKeyX,
        mExchanges[clientId].clientPubKeyY,
        &pubKey
    );
    EC_KEY *key;
    // TODO: clean
    mMessage->get_ephemeral_key(&key);
    ecdhe_get_shared_key(key, pubKey, &sharedKey);
    memcpy(mExchanges[clientId].sharedKey, sharedKey, KEY_LEN);
    //printf("SHARED KEY: %s\n", bin2hex(mExchanges[clientId].sharedKey, KEY_LEN));

    EC_POINT_free(pubKey);
    mMessage->set_key(sharedKey);
    
    // Create AAD
    unsigned char *up = json_to_unsigned_char(upJson, JSON_COMPACT);
    int upLen = strlen((const char *)up);
    int message1Len = strlen((const char*)mExchanges[clientId].message1);
    int aadTextLen = message1Len + upLen;
    unsigned char *aadText = new unsigned char[aadTextLen];
    memcpy(aadText, mExchanges[clientId].message1, message1Len);
    memcpy(aadText + message1Len, up, upLen);
    delete[] up;
    unsigned char *aad = new unsigned char[SHA256_DIGEST_LENGTH];
    SHA256(aadText, aadTextLen, aad);
    //printf("aad2 text: %s\n", aadText);
    //printf("aad2: %s\n", bin2hex(aad, 32));
    mMessage->set_aad(aad);
    memcpy(mExchanges[clientId].aad2, aad, SHA256_DIGEST_LENGTH);
    delete[] aadText;

    // Create signature
    ECDSA_SIG *sig;
    sig = ECDSA_do_sign(aad, SHA256_DIGEST_LENGTH, mMainKey);

    const BIGNUM *r, *s;
    //sig2bn(sig, &r, &s);
    ECDSA_SIG_get0(sig, &r, &s);
    //printf("\nsignature:\n");
    //printf("r: %s\n", BN_bn2hex(r));
    //printf("s: %s\n\n", BN_bn2hex(s));
    mMessage->set_signature(r, s);
    ECDSA_SIG_free(sig);

    // Derive encryption key
    ecdhe_create_encryption_key(mMessage);

    // Derive encryption IV
    ecdhe_create_iv(mMessage);

    // Encrypt message
    ecdhe_encrypt_signature(mMessage);

    // Build message
    json_t *json = json_object();
    mMessage->get_unprotected_message(&upJson);

    json_object_set(json, "unprotected", upJson);
    mMessage->json_add_cipher(json);
    mMessage->set_message(&json);
    mMessage->get_text_message_len(message2_len);

    return 1;
}

int AuthManager::check_message_3(const char *message3, int clientId)
{
    // TODO: check that client exists in DB and in exchanges
    int ret;
    //printf("\nStarting check of message 3\n");
    if(mMessage != NULL){
        //printf("mMessage is not null!\n");
        delete mMessage;
    }
    mMessage = new ECDHE_M();
    json_error_t error;
    json_auto_t *message3Json = json_loads(message3, 0, &error);
    json_t *upJson = json_object_get(message3Json, "unprotected");
    unsigned char *up = json_to_unsigned_char(upJson, JSON_COMPACT);

    // Build aad3
    int upLen = strlen((const char *)up);
    //printf("up: %d: %s\n", upLen, up);

    char *aad2B64 = bin2b64url(mExchanges[clientId].aad2, SHA256_DIGEST_LENGTH);
    int aad2B64Len = strlen((const char *)aad2B64);
    int aad3TextLen = aad2B64Len + upLen;
    unsigned char *aad3Text = new unsigned char[aad3TextLen];
    memcpy(aad3Text, aad2B64, aad2B64Len);
    delete[] aad2B64;
    memcpy(aad3Text + aad2B64Len, up, upLen);
    delete[] up;

    unsigned char *aad3 = new unsigned char[SHA256_DIGEST_LENGTH];
    SHA256(aad3Text, aad3TextLen, aad3);
    delete[] aad3Text;
    //printf("aad3 text: %s\n", aad3Text);
    //printf("aad3 from msg3 check: %s\n", bin2hex(aad3, SHA256_DIGEST_LENGTH));

    mMessage->set_aad(aad3);
    unsigned char *sharedKey = new unsigned char[KEY_LEN];
    memcpy(sharedKey, mExchanges[clientId].sharedKey, KEY_LEN);
    mMessage->set_key(sharedKey);

    // Derive encryption key
    ecdhe_create_encryption_key(mMessage);

    // Derive IV
    ecdhe_create_iv(mMessage);

    // Decrypt signature
    json_t *cipher3Json = json_object_get(message3Json, "ciphertext");
    const char *cipher3B64 = json_string_value(cipher3Json);
    int cipher3Len;
    unsigned char *cipher3 = b64url2bin((char *)cipher3B64, &cipher3Len);
    //printf("cipher3: %s\n", bin2hex(cipher3, cipher3Len));
    //json_print(message3Json);

    json_t *tag3Json = json_object_get(message3Json, "tag");
    int tag3Len;
    const char *tag3B64 = json_string_value(tag3Json);
    unsigned char *tag3 = b64url2bin((char *)tag3B64, &tag3Len);

    mMessage->set_cipher(cipher3, cipher3Len, tag3);
    ecdhe_decrypt_signature(mMessage);
    
    // Verify signature
    EC_KEY *clientKey;
    MClient *client = new MClient(mDb);
    client->set_id(clientId);
    client->get_by_id();
    ec_key_from_hex_public_coordinates(
        &clientKey, 
        (const char *)client->get_pub_key_x_hex(), 
        (const char *)client->get_pub_key_y_hex()
    );

    //printf("client pub key x: %s\n", client->get_pub_key_x_hex());
    //printf("client pub key y: %s\n", client->get_pub_key_y_hex());

    //printf("client pub key x: %s\n", hex2b64url((const char *)client->get_pub_key_x_hex()));
    //printf("client pub key y: %s\n", hex2b64url((const char *)client->get_pub_key_y_hex()));


    json_t *signature;
    mMessage->get_json_signature(&signature);
    //(signature);
    const char *r = json_string_value(json_object_get(signature, "r"));
    const char *s = json_string_value(json_object_get(signature, "s"));
    BIGNUM *rB, *sB;
    rB = b64url2bn((unsigned char *)r);
    sB = b64url2bn((unsigned char *)s);

    ECDSA_SIG *sig = ECDSA_SIG_new();
    //sig = bn2sig(rB, sB);
    ECDSA_SIG_set0(sig, rB, sB);
    mMessage->get_aad(&aad3);
    ret = ECDSA_do_verify(aad3, SHA256_DIGEST_LENGTH, sig, clientKey);
    //printf("ret of signature verification: %d\n", ret);
    ECDSA_SIG_free(sig);
    EC_KEY_free(clientKey);

    if(ret != 1){
        return 0;
    }

    return 1;

}

int AuthManager::create_message_4(int clientId, int *message4_len)
{
    int res;
    // Create session
    mSessions[clientId] = {};
    unsigned char *key;
    ecdhe_create_session_key(mMessage);
    mMessage->get_session_key(&key);
    memcpy(mSessions[clientId].key, key, KEY_LEN);
    delete[] key;

    // Create new session and increment session ID
    int sessionId;
    res = increment_and_get_session_id(&sessionId);
    mSessions[clientId].sessionId = sessionId;
    mSessions[clientId].clientId = clientId;
    mDirectory[sessionId] = clientId;
    // TODO: set expiry time

    json_t *message = json_pack("{s:i}", "kid", mSessions[clientId].sessionId);
    mMessage->set_message(&message);
    mMessage->get_text_message_len(message4_len);
    //printf("created session with key: %s\n", bin2hex((unsigned char *)mSessions[clientId].key, KEY_LEN));
    return 1;
}

int AuthManager::increment_and_get_session_id(int *id)
{
    int res;
    const char *requestUpdate = "UPDATE sessions_count SET counter = counter + 1;";

    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*mDb, requestUpdate, -1, &statement, NULL);
    res = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if(res != SQLITE_DONE) {
        return err("error incrementing session", error_misc);
    }

    const char *requestGet = "SELECT counter FROM sessions_count;";

    sqlite3_prepare_v2(*mDb, requestGet, -1, &statement, NULL);
    res = sqlite3_step(statement);
    if(res != SQLITE_ROW) {
        sqlite3_finalize(statement);
    }
    *id = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);

    return 1;
}

int AuthManager::decrypt_session_message(Request *request)
{
    int ret;
    // Get session
    json_t *jwe = request->get_request_jwe();

    // Validate json
    ret = json_unpack_ex(jwe, NULL, JSON_VALIDATE_ONLY + JSON_STRICT,
        "{s:{s:s,s:i},s:s,s:s,s:s}",
        "unprotected", "alg", "kid", "iv", "ciphertext", "tag"
    );
    if(ret == -1) return err("invalid JSON JWE", error_misc);
    // Get session ID
    int kid = json_integer_value(
        json_object_get(
            json_object_get(jwe, "unprotected"), 
            "kid"
        )
    );
    if(mDirectory.count(kid) == 0) return err("session not found", error_misc);
    request->set_session(&mSessions[mDirectory[kid]]);
    ret = mInterceptor.decrypt_request(request);
    if(ret != 1) return err("could not decrypt request", error_misc);
    return 1;
}

int AuthManager::authenticate(Request *request)
{
    int ret;
    session *session = request->get_session();
    MClient *client = new MClient(mDb);
    client->set_id(session->clientId);
    ret = client->get_by_id();
    if(ret != 1) return err("cannot find client (should not happen)", error_misc);

    request->set_client(client);
    if(!(client->get_is_active())) return err("client is not active (should not happen)", error_misc);
    // TODO: Check if is admin
    return 1;
}

int AuthManager::encrypt_session_response(Request *request)
{
    mInterceptor.encrypt_response(request);
}