#ifndef REQUEST_H
#define REQUEST_H

#include <string>
#include <map>
#include "../models/client.h"
#include <openssl/sha.h>
#include "../auth/session.h"

using namespace std;


class Request{
    public:
        Request();
        ~Request();


        // Request

        string get_request_string();
        void set_request_string(string str);

        string get_message();
        void set_message(string payload);

        string get_path();
        void set_path(string path);

        string get_method();
        void set_method(string method);

        string get_uri();
        void set_uri(string uri);

        string get_path_parameter(string key);
        void set_path_parameter(string key, string value);
        void clear_path_parameters();

        string get_query_parameter(string key);
        void set_query_parameter(string key, string value);

        string get_headers();
        void set_headers(string headers);

        map<string, string> get_query_parameters();

        // Sender
        MClient *get_client();
        void set_client(MClient *client);

        void set_backup(int backup);
        int get_backup();

        void set_dump(string dump);
        string get_dump();
        void set_event_id(int eventId);
        int get_event_id();

        // Session
        session *get_session();
        void set_session(session *session);
        json_t *get_request_jwe();
        void set_request_jwe(json_t *jwe);
        json_t *get_response_jwe();
        void set_response_jwe(json_t *jwe);
        
        // Response
        string get_response_string();
        void set_response_string(string response);
        int get_response_length();
        string get_response_message();
        void set_response_message(string response);
        int get_status_code();
        void set_status_code(int statusCode);
        

    private:
        // Session
        session *mSession;

        MClient *mClient;

        int mBackup;

        // Request
        json_t *mJwe;
        string mRequestString;
        string mMessage;
        string mHeaders;
        string mMethod;
        string mPath;
        string mUri;
        map<string, string> mPathParameters;
        map<string, string> mQueryParameters;
        string mDump;
        int mEventId;

        // Response
        string mResponseString;
        string mResponseMessage;
        int mStatusCode;

};



#endif