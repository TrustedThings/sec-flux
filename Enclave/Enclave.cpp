
#include "Enclave_t.h"
#include "request/request_manager.h"
#include "auth/auth_manager.h"
#include "database/data_manager.h"
#include "duktape.h"
#include "request/http_responses.h"

using namespace std;

RequestManager requestManager;
AuthManager authManager;
DataManager dataManager;

// Ecalls

void enclave_init()
{
  dataManager.init("database");
  requestManager.init(dataManager.get_db_ptr());
  authManager.init(dataManager.get_db_ptr());

  return;
}

void auth_do_request(int step, const char *body, int clientId, int *response_length)
{
  int ret;
  // Step 1
  if(step == 1){
    ret = authManager.step1(body, clientId, response_length);
    if(ret != 1){
      authManager.print_error();
      *response_length = -1;
    }
  }
  // Step 2
  else{
    ret = authManager.step2(body, clientId, response_length);
    if(ret != 1){
      authManager.print_error();
      *response_length = -1;
    }
  }
  return;
}

void auth_get_response(char *response, int *status_code)
{
  *status_code = 200;
  char *tmp;
  authManager.get_message(&tmp);
  memcpy(response, tmp, strlen((const char *)tmp) + 1);
  delete[] tmp;
  return;

}

void request_do_request(
    char *method,
    char *uri,
    char *headers,
    char *jweIn,
    const char *data, 
    int *response_length
)
{
    int ret;
    //printf("method: %s\nuri: %s\nheaders: %s\njwe: %s\ndata: %s\n", method, uri, headers, jweIn, data);
    
    // Set new request elements
    Request *request = new Request();
    requestManager.set_request(request);  
    request->set_headers(headers);
    request->set_method(method);
    request->set_uri(uri);
    // Get JWE
    json_error_t jsonError;
    json_auto_t *jwe;
    // Error: no JWT
    if(jweIn == NULL && strlen(data) == 0) {
        http_unauthorized(request);
    } else{
        // JWE in payload
        if(strlen(data) > 0) {
            jwe = json_loads(data, 0, &jsonError);
        } 
        // JWE in query, recompose it
        else {
            jwe = jwt2jwe(jweIn);
        }
        if(jwe == NULL){
            http_unauthorized(request);
        } else {
            request->set_request_jwe(jwe);
            // Decrypt request
            ret = authManager.decrypt_session_message(request);
            if(ret == 0) {
                http_unauthorized(request);
            } else {
                // Authenticate client (active and admin rights)
                ret = authManager.authenticate(request);
                // Forbidden
                if(ret == 0) {
                    http_forbidden(request);
                } else {  
                    int backup = 0;
                    requestManager.do_request(&backup);
                    if(backup == 1) {
                        // Increment model version
                        dataManager.increment_version();
                        // Save entire model
                        dataManager.seal_db();
                    } else if(backup == 2) {
                        // Archive event
                        string filename = "data/events/" + to_string(request->get_event_id()) + ".seal";
                        dataManager.archive_event(request->get_dump().c_str(), filename.c_str());
                    }
                    authManager.encrypt_session_response(request);
                }
            }
        }
        
    }
    *response_length = requestManager.get_response_length();
    
}

void request_get_response(char *data, int *in_body, int *statusCode)
{
    Request *request = requestManager.get_request();
    string response = request->get_response_string();
    *statusCode = request->get_status_code();
    *in_body = request->get_status_code() == 204 ? 0 : 1;
    memcpy(data, response.c_str(), response.length() + 1);
    
}


