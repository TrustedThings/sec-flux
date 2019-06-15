#include "../models/client.h"
#include <jansson.h>
#include "../utils.h"
#include "../crypto/crypto.h"
#include "interceptor.h"
#include "session.h"
#include <openssl/rand.h>
#include "../crypto/b64url.h"

Interceptor::Interceptor()
{
}

Interceptor::~Interceptor()
{
}

int Interceptor::init(sqlite3 **db)
{
    mDb = db;
}

int Interceptor::decrypt_request(Request *request)
{
    session *session = request->get_session();
    int ret;
    // Parse jwe
    json_t *jwe = request->get_request_jwe();
    const char *alg, *b64Iv, *b64Ciphertext, *b64Tag;
    int kid;
 
    // Extract json
    ret = json_unpack(
        jwe, 
        "{s:{s:s,s:i},s:s,s:s,s:s!}",
        "unprotected",
        "alg", &alg, 
        "kid", &kid,
        "iv", &b64Iv,
        "ciphertext", &b64Ciphertext,
        "tag", &b64Tag
    );
    if(ret == -1) return err("malformed jwe (should not happen!)", error_misc);
    // Decrypt jwe
    int len;
    unsigned char *iv, *ciphertext, *tag;
    iv = b64url2bin((char *)b64Iv, &len);
    if(len != IV_LEN) return err("wrong IV size", error_misc);

    tag = b64url2bin((char *)b64Tag, &len);
    if(len != TAG_LEN) return err("wrong tag size", error_misc);

    // Create aad
    string aadString = ":" + request->get_method() + ":" + request->get_uri();
    unsigned char *aad = new unsigned char[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)(aadString.c_str()), aadString.size(), aad);
    //memcpy(aad, aadString.c_str(), aadString.size());
    ciphertext = b64url2bin((char *)b64Ciphertext, &len);
    unsigned char *plaintext = new unsigned char[len + 1];
    //plaintext = new unsigned char[len + 1];
    error_t error;
    ret = aes_256_gcm_decrypt(
        ciphertext, len,
        plaintext, &(session->key[0]),
        iv, tag, 
        aad, SHA256_DIGEST_LENGTH, &error
    );

    delete[] iv;
    if(ciphertext != NULL) delete[] ciphertext;
    delete[] tag;
    delete[] aad;
    if(ret == 0) return err("could not decrypt JWE", error_misc);
    plaintext[len] = '\0';

    // Set payload if present
    if(len > 0) {
        request->set_message((char *)plaintext);
    }
    delete[] plaintext;
    /*
    json_error_t jsonError;
    json_auto_t *json = json_loads((const char *)plaintext, 0, &jsonError);
    json_print(json);
    if(json == NULL) {
        // TODO: encrypt error message
    }
    // Parse payload
    int cid;
    const char *method, *url;
    ret = json_unpack(json, "{s:i,s:s,s:s}",
        "cid", &cid,
        "method", &method,
        "url", &url
    );

    if(ret == -1) {
        // TODO: encrypt error message
    }

    if(cid != session->clientId) {
        // TODO: encrypt error message
    }
    */

    // Set query string and parameters
    string uri = request->get_uri();
    string path = uri;
    string queryString = "";
    size_t pos = uri.find('?');
    if(pos != string::npos){
        path = uri.substr(0, pos);
        queryString = uri.substr(pos + 1);
    }
    request->set_path(path);

    // Set query parameters
    string del1= "&";
    string del2 = "=";
    size_t pos1, pos2;
    string p;
    while(true){
        pos1 = queryString.find(del1);
        p = queryString.substr(0, pos1);
        pos2 = p.find(del2);
        if(pos2 != string::npos && pos2 != 0 && pos2 != p.length() - 1) {
            request->set_query_parameter(p.substr(0, pos2), p.substr(pos2 + 1));
        }
        if(pos1 == string::npos) break;
        queryString.erase(0, pos1 + del1.length());
    }

    //request->set_method(method);

    // Set message if present
    /*
    string m = request->get_method();
    if(m.compare("GET") != 0 && m.compare("DELETE") != 0) {
        json_t *jsonMessage = json_object_get(json, "message");
        if(jsonMessage == NULL) {
            // TODO: manage error
            printf("no message!\n");
        }
        const char *message = json_dumps(jsonMessage, 0);
        request->set_message(message);
    } 
    */

    return 1;

}

int Interceptor::encrypt_response(Request *request)
{
    int ret;

    // Retrieve key
    session *session = request->get_session();
    
    // Generate AAD
    unsigned char aad[SHA256_DIGEST_LENGTH];
    string aadText = ":";
    aadText.append(json_string_value(json_object_get(request->get_request_jwe(), "tag")));
    aadText.append(":" + to_string(request->get_status_code()));
    SHA256((const unsigned char *)aadText.c_str(), aadText.size(), aad);

    // Generate IV
    unsigned char iv[IV_LEN];
    ret = RAND_bytes(iv, IV_LEN);

    // Generate plaintext
    /*
    int statusCode = request->get_status_code();
    json_auto_t *jsonPlaintext = json_pack("{s:i}",
        "code", statusCode
    );
    */
  
    // Add message?
    string message = request->get_response_message();
    int len = message.size();
    char *plaintext = new char[len];
    memcpy(plaintext, message.c_str(), len);
    unsigned char ciphertext[len];

    // Encrypt response
    unsigned char tag[TAG_LEN];
    error_t error;
    ret = aes_256_gcm_encrypt((unsigned char *)plaintext,
        len, ciphertext, session->key, iv,
        tag, aad, SHA256_DIGEST_LENGTH, &error
    );
    
    delete[] plaintext;

    char *b64Iv = bin2b64url(iv, IV_LEN);
    char *b64Ciphertext = bin2b64url(ciphertext, len);
    char *b64Tag = bin2b64url(tag, TAG_LEN);
    
    if(request->get_status_code() == 204) {
        string jwt = "";
        string headers = "{\"alg\":\"dir\",\"kid\":" + to_string(session->sessionId) + "}";
        char *b64Headers = b64url_encode((const unsigned char *)(headers.c_str()), headers.size());
        jwt.append(b64Headers);
        jwt.append("..");
        jwt.append(b64Iv);
        jwt.append(".");
        jwt.append(b64Ciphertext);
        jwt.append(".");
        jwt.append(b64Tag);

        free(b64Headers);
        request->set_response_string(jwt);

    } else {
        json_auto_t *jwe = json_pack("{s:{s:s,s:i},s:s,s:s,s:s}",
            "unprotected",
            "alg", "dir", 
            "kid", session->sessionId, 
            "iv", b64Iv,
            "ciphertext", b64Ciphertext, 
            "tag", b64Tag
        );
        char *response = json_dumps(jwe, JSON_COMPACT);
        request->set_response_string(response);
        free(response);
    }
    
    free(b64Iv);
    free(b64Ciphertext);
    free(b64Tag);
    
    return 1;

}