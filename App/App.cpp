
#include <string.h>
#include <assert.h>
#include <fstream>
#include <thread>
#include <iostream>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_tseal.h"

#include "ErrorSupport.h"

#include <memory>
#include <restbed>
#include <cstdlib>

#include <sqlite3.h>

using namespace std;
using namespace restbed;

#define ENCLAVE_NAME "libenclave.signed.so"
#define TOKEN_NAME "Enclave.token"

// Global data
sgx_enclave_id_t global_eid = 0;
sgx_launch_token_t token = {0};

Service service;

string response;
int status_code;

// Benchmark
int ind = 0;
int n = 1100;
struct timespec startT, endT;
unsigned long long elapsed_msg1=0, elapsed_msg3=0, elapsed_session=0;
uint64_t t;
uint64_t ticks_encrypt=0, ticks_decrypt=0;

// load_and_initialize_enclave():
//		To load and initialize the enclave
sgx_status_t load_and_initialize_enclave(sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_SUCCESS;
    int retval = 0;
    int updated = 0;

	// Step 1: check whether the loading and initialization operations are caused by power transition.
	//		If the loading and initialization operations are caused by power transition, we need to call sgx_destory_enclave() first.
	if(*eid != 0)
	{
		sgx_destroy_enclave(*eid);
	}

	// Step 2: load the enclave
	// Debug: set the 2nd parameter to 1 which indicates the enclave are launched in debug mode
	ret = sgx_create_enclave(ENCLAVE_NAME, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
	if(ret != SGX_SUCCESS)
		return ret;

	// Save the launch token if updated
	if(updated == 1)
	{
		ofstream ofs(TOKEN_NAME, std::ios::binary|std::ios::out);
		if(!ofs.good())
		{
			cout<< "Warning: Failed to save the launch token to \"" <<TOKEN_NAME <<"\""<<endl;
		}
		else
			ofs << token;
	}
    return ret;
}


void set_response(const char *encl_res, int encl_status_code)
{
    response = encl_res;
    status_code = encl_status_code;
}

void auth(const shared_ptr<Session> session, int step)
{
    const auto request = session->get_request();
    int client_id = stoi(request->get_path_parameter("clientId"));
    size_t content_length = request->get_header("Content-Length", 0);
    session->fetch(content_length, [request, step, client_id, content_length](const shared_ptr<Session> session, const Bytes & body)
    {
        sgx_status_t ret;
        int response_length;
        char *data = new char[content_length + 1];
        memcpy(data, body.data(), content_length);
        data[content_length] = '\0';
        ret = auth_do_request(
            global_eid, 
            step, 
            data, 
            client_id,
            &response_length
        );
        if(response_length == -1){
            const char *error = "Error";
            session->close(400, error, {{"Content-Length", std::to_string(strlen(error))}});
            return;
        }
        char *response = new char[response_length];
        memset(response, '-', response_length - 1);
        response[response_length - 1] = '\0';
        int status_code;
        ret = auth_get_response(global_eid, response, &status_code);
        session->close(status_code, response, {{"Content-Length", std::to_string(strlen(response))}});
    });
}
/*
void entrypoint(const shared_ptr<Session> session)
{
    clock_gettime(CLOCK_MONOTONIC, &startT);
    const auto request = session->get_request();
    size_t content_length = request->get_header("Content-Length", 0);
    session->fetch(content_length, [request, content_length](const shared_ptr<Session> session, const Bytes & body)
    {
        sgx_status_t ret;
        int response_length;
        char *data = new char[content_length + 1];
        memcpy(data, body.data(), content_length);
        data[content_length] = '\0';
        ret = request_do_request(
            global_eid, 
            data, 
            &response_length
        );
        if(response_length == -1){
            const char *error = "Error";
            session->close(400, error, {{"Content-Length", std::to_string(strlen(error))}});
            return;
        }
        char *response = new char[response_length];
        memset(response, '-', response_length - 1);
        response[response_length - 1] = '\0';
        int status_code;
        ret = request_get_response(global_eid, response, &status_code);
        session->close(status_code, response, {{"Content-Length", std::to_string(strlen(response))}});
    });
    clock_gettime(CLOCK_MONOTONIC, &endT);
    if(ind > 0) elapsed_session += (endT.tv_sec - startT.tv_sec) * (long) 1e9 + (endT.tv_nsec - startT.tv_nsec);
    ind += 1;
    if(ind == n + 1) {
        ind = 0;
            printf("session:\t%f\tns\n", ((double)elapsed_msg1)/n);
    }
}
*/

void endpoint_handler(const shared_ptr<Session> session)
{
    clock_gettime(CLOCK_MONOTONIC, &startT);
    const auto request = session->get_request();
    size_t content_length = request->get_header("Content-Length", 0);
    session->fetch(content_length, [request, content_length](const shared_ptr<Session> session, const Bytes & body)
    {
        sgx_status_t ret;
        int response_length;
        // Get Payload
        char *data = new char[content_length + 1];
        memcpy(data, body.data(), content_length);
        data[content_length] = '\0';

        // Get path
        string p = request->get_path() + "?";

        // Get query and jwe
        char *jwe = NULL;
        multimap<string, string> q = request->get_query_parameters();
        for(multimap<string, string>::iterator it = q.begin(); it != q.end(); ++it) {
            if((*it).first.compare("jwe") == 0) {
                jwe = new char[(*it).second.size() + 1];
                memcpy(jwe, (*it).second.c_str(), (*it).second.size() + 1);
            } else {
                p += (*it).first + "=" + (*it).second + "&";
            }
        }
        
        // Build URI
        char *uri = new char[p.size()];
        memcpy(uri, p.c_str(), p.size() - 1);
        uri[p.size() - 1] = '\0';
        
        // Get method
        string m = request->get_method();
        char *method = new char[m.size() + 1];
        memcpy(method, m.c_str(), m.size() + 1);

        // Get headers
        // TODO: get significant headers to add
        char *headers = new char[1];
        headers[0] = '\0';

        ret = request_do_request(
            global_eid, 
            method,
            uri,
            headers,
            jwe,
            data, 
            &response_length
        );
        if(response_length == -1){
            const char *error = "Error";
            session->close(400, error, {{"Content-Length", std::to_string(strlen(error))}});
            return;
        }
        char *response = new char[response_length];
        memset(response, '-', response_length - 1);
        response[response_length - 1] = '\0';
        int status_code, in_body;
        ret = request_get_response(global_eid, response, &in_body, &status_code);
        if(in_body) {
            session->close(status_code, response, {
                {"Content-Length", std::to_string(strlen(response))}
            });
        } else {
            session->close(status_code, response, {
                {"Content-Length", "0"},
                {"X-Auth", response}
            });
        }
    });
    clock_gettime(CLOCK_MONOTONIC, &endT);
    if(ind > 100) elapsed_session += (endT.tv_sec - startT.tv_sec) * (long) 1e9 + (endT.tv_nsec - startT.tv_nsec);
    ind += 1;
    if(ind == n) {
        ind = 0;
        printf("session message:\t%f\tns\n", ((double)elapsed_session)/n);
    }
}

// ECDHE step 1
void auth1( const shared_ptr<Session> session)
{
    clock_gettime(CLOCK_MONOTONIC, &startT);
  auth(session, 1);
  clock_gettime(CLOCK_MONOTONIC, &endT);
    elapsed_msg1 += (endT.tv_sec - startT.tv_sec) * (long) 1e9 + (endT.tv_nsec - startT.tv_nsec);
}

// ECDHE step 2
void auth2( const shared_ptr< Session > session)
{
    clock_gettime(CLOCK_MONOTONIC, &startT);
  auth(session, 2);
  clock_gettime(CLOCK_MONOTONIC, &endT);
    elapsed_msg3 += (endT.tv_sec - startT.tv_sec) * (long) 1e9 + (endT.tv_nsec - startT.tv_nsec);
    //ind += 1;
    if(ind == n) {
        ind = 0;
    printf("message1_handler:\t%f\tns\n", ((double)elapsed_msg1)/n);
    printf("message3_handler:\t%f\tns\n", ((double)elapsed_msg3)/n);
    }
}

void register_endpoint(string path, vector<string> methods)
{
    auto resource = make_shared<Resource>();
    resource->set_path(path);
    for(vector<string>::iterator it = methods.begin(); it != methods.end(); it++) {
        resource->set_method_handler(*it, endpoint_handler);
    }
    resource->set_method_handler("OPTIONS", [](std::shared_ptr<restbed::Session> session) { session->close(restbed::OK, ""); } );
    service.publish(resource);
}

int main(int argc, char* argv[])
{
    (void)argc, (void)argv;
    // Load and initialize the signed enclave
    // sealed_buf == NULL indicates it is the first time to initialize the enclave.
    sgx_status_t ret = load_and_initialize_enclave(&global_eid);
    if(ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        cout << "Enter a character before exit ..." << endl;
        getchar();
        return -1;
    }
    enclave_init(global_eid);
    //init_client(global_eid);
    
    auto settings = make_shared< Settings >( );
    settings->set_port( 1984 );
    settings->set_default_header( "Connection", "close" );
    settings->set_default_header( "Access-Control-Allow-Origin", "*" );
    settings->set_default_header( "Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE");
    settings->set_default_header( "Access-Control-Allow-Headers", "Content-Type");
    settings->set_default_header( "Access-Control-Expose-Headers", "X-Auth");

    register_endpoint("/actiontemplates/", {"GET", "POST"});
    register_endpoint("/actiontemplates/{actionTemplateId: .*}", {"GET", "PUT", "DELETE"});

    register_endpoint("/actiontypes/", {"GET", "POST"});
    register_endpoint("/actiontypes/{actionTypeId: .*}", {"GET", "PUT", "DELETE"});

    register_endpoint("/clients/", {"GET", "POST"});
    register_endpoint("/clients/{clientId: .*}", {"GET", "PUT", "DELETE"});
    register_endpoint("/clients/{clientId: .*}/actions/", {"GET"});
    register_endpoint("/clients/{clientId: .*}/actions/{actionId: .*}", {"GET"});

    register_endpoint("/context/eval", {"POST"});

    register_endpoint("/eventtypes/", {"GET", "POST"});
    register_endpoint("/eventtypes/{eventTypeId: .*}", {"GET", "PUT", "DELETE"});

    register_endpoint("/events/", {"GET", "POST"});
    register_endpoint("/events/{eventId: .*}", {"GET", "DELETE"});

    register_endpoint("/rules/", {"GET", "POST"});
    register_endpoint("/rules/{ruleId: .*}", {"GET", "PUT", "DELETE"});

    register_endpoint("/version", {"GET"});


    auto resource = make_shared< Resource >( );
    /*
    resource->set_path( "/entrypoint" );
    resource->set_method_handler( "POST", entrypoint );
    resource->set_method_handler("OPTIONS", [](std::shared_ptr<restbed::Session> session) { session->close(restbed::OK, ""); } );
    service.publish( resource );
    */
    

    // ECDHE step 1
    resource = make_shared< Resource >( );
    resource->set_path( "/clients/{clientId: .*}/auth1" );
    resource->set_method_handler( "POST", auth1 );
    resource->set_method_handler("OPTIONS", [](std::shared_ptr<restbed::Session> session) { session->close(restbed::OK, ""); } );
    service.publish( resource );

    // ECDHE step 2
    resource = make_shared< Resource >( );
    resource->set_path( "/clients/{clientId: .*}/auth2" );
    resource->set_method_handler( "POST", auth2 );
    resource->set_method_handler("OPTIONS", [](std::shared_ptr<restbed::Session> session) { session->close(restbed::OK, ""); } );
    service.publish( resource );

    // Service termination
    resource = make_shared< Resource >();
    resource->set_path("/shutdown");
    resource->set_method_handler("GET", [](std::shared_ptr<restbed::Session> session) { 
        sgx_destroy_enclave(global_eid); 
        session->close(restbed::OK, "");
        } );
    service.publish( resource );

    service.start( settings );
    return 0;
}



void uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
    fflush(stdout);
}

// ocalls for printing string (C++ ocalls)
void ocall_print_error(const char *str){
    cerr << str << endl;
}

void ocall_print_string(const char *str){
    cout << str;
}

void ocall_println_string(const char *str){
    cout << str << endl;
}

void ocall_save_data(char *data, size_t len, const char *filename)
{
    ofstream f(filename, ios::out | ios::binary);
    f.write(data, len);
    f.close();
}

void ocall_load_data(char *data, size_t len, const char *filename)
{
    ifstream f(filename, ios::in | ios::binary);
    f.read(data, len);
    f.close();
}

void ocall_get_data_size(const char *filename, size_t *len)
{
    ifstream f(filename, ios::in | ios::binary | ios::ate);
    if(f.fail()) {
        *len = 0;
        return;
    } 
    fstream::pos_type size = f.tellg();
    *len = size;
    f.close();

}