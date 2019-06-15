#include "client.h"
#include "Enclave_t.h"
#include "request/request_manager.h"
#include "utils.h"
#include "request/request.h"


char *clientToken = NULL;
char *clientPayload = NULL;

extern RequestManager requestManager;

/**
MSession *clientSession;
SESSION_JWT *clientJwt;
SESSION_JWE *clientJwe;
**/

const char *sessionKey = "60322a132f263fd64bd9dc6cdfb8c7512e7d093913d84baf7f986a10a4ef8692";


void init_client()
{
    /**
    int ret;
    
    const char *pubX = "2F48B4F13E167892A065168C967568B0236723AB3371554921246A1E1D98D554";
    const char *pubY = "F6AE0EA7C9B2E5C0775D3E4EA78DDE365BE3AAFF8C9B63894FAD006450F95F09";
    clientSession = new MSession(requestManager.get_db_ptr());
    clientSession->set_key_hex((unsigned char *)sessionKey, true);
    ret = clientSession->get_by_key_hex();
    // Insert new session
    if(ret != 1){
        MClient client(requestManager.get_db_ptr());
        client.set_name((unsigned char *)"George", true);
        client.set_is_admin(1);
        client.set_is_active(1);
        client.set_pub_key_x_hex((unsigned char *)pubX, true);
        client.set_pub_key_y_hex((unsigned char *)pubY, true);
        ret = client.save();
        
        clientSession->set_client_id(client.get_id());
        clientSession->set_last_iv_hex((unsigned char *)"lol", true);
        clientSession->save();
    }
    **/
}   


void test_in(string method, string uri)
{
    /**
    
    Request *request = requestManager.get_request();
    if(clientJwt != NULL) delete clientJwt;
    clientJwt = new SESSION_JWT();

    // JWE and JWT present, create JWE and set MAG
    string jweStr = request->test_get_jwe();
    if(!jweStr.empty()){
        if(clientJwe != NULL) delete clientJwe;
        clientJwe = new SESSION_JWE();
        const char *tmp = jweStr.c_str();
        unsigned char *plaintext = new unsigned char[strlen(tmp) + 1];
        memcpy(plaintext, tmp, strlen(tmp) + 1);
        clientJwe->set_plaintext(plaintext);
        clientJwe->encrypt(clientSession);
        request->set_request_jwe(clientJwe->get_text_jwe());
        unsigned char *mag = new unsigned char[TAG_LEN];
        unsigned char *tag = clientJwe->get_tag();
        memcpy(mag, tag, TAG_LEN);
        clientJwt->set_mag(mag);
    } 

    string tmp = method + ":" + uri;
    unsigned char *aad = new unsigned char[tmp.size() + 1];
    memcpy(aad, tmp.c_str(), tmp.size() + 1);
    clientJwt->set_aad(aad);
    clientJwt->encrypt(clientSession);
    request->set_request_jwt((const char *)clientJwt->get_text_jwt());
    //request->set_uri(uri);
    **/
}

void test_out()
{
    /**
    Request *request = requestManager.get_request();
    SESSION_JWE sJwe;
    const char *response;
    int code;
    request->get_response(&response, &code);
    char *res = new char[strlen(response) + 1];
    memcpy(res, response, strlen(response) + 1);
    sJwe.set_text_jwe(res);
    int ret = sJwe.decrypt(clientSession);
    json_error_t error;
    json_auto_t *json = json_loads((const char *)sJwe.get_plaintext(), 0, &error);
    request->test_set_response(json_object_get(json, "message"));
**/
}