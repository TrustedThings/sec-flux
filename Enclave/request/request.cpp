#include "request.h"

Request::Request()
{
    mClient = NULL;
    //mJwe = NULL;
    mStatusCode = 500;
    mBackup = 0;
}

Request::~Request()
{
  if(mClient != NULL) delete mClient;
  //if(mJwe != NULL) json_decref(mJwe);
}

void Request::set_backup(int backup)
{
    mBackup = backup;
}

int Request::get_backup()
{
    return mBackup;
}

string Request::get_request_string()
{
    return mRequestString;
}

void Request::set_request_string(string str)
{
    mRequestString = str;
}

string Request::get_message()
{
    return mMessage;
}

void Request::set_message(string message)
{
    mMessage = message;
}

string Request::get_path()
{
    return mPath;
}

void Request::set_path(string path)
{
    mPath = path;
}

string Request::get_headers()
{
    return mHeaders;
}

void Request::set_headers(string headers)
{
    mHeaders = headers;
}

string Request::get_method()
{
    return mMethod;
}

void Request::set_method(string method)
{
    mMethod = method;
}

string Request::get_uri()
{
    return mUri;
}

void Request::set_uri(string uri)
{
    mUri = uri;
}

string Request::get_path_parameter(string key)
{
  return mPathParameters[key];
}

void Request::set_path_parameter(string key, string value)
{
  mPathParameters[key] = value;
}

void Request::clear_path_parameters()
{
    mPathParameters.clear();
}

string Request::get_query_parameter(string key)
{
  return mQueryParameters[key];
}

void Request::set_query_parameter(string key, string value)
{
    mQueryParameters[key] = value;
}

map<string, string> Request::get_query_parameters()
{
    return mQueryParameters;
}

MClient *Request::get_client()
{
    return mClient;
}

void Request::set_client(MClient *client)
{
    mClient = client;
}

session *Request::get_session()
{
    return mSession;
}

void Request::set_session(session *session)
{
    mSession = session;
}

json_t *Request::get_request_jwe()
{
    return mJwe;
}

void Request::set_request_jwe(json_t *jwe)
{
    mJwe = jwe;
}

json_t *Request::get_response_jwe()
{
    return mJwe;
}

void Request::set_response_jwe(json_t *jwe)
{
    mJwe = jwe;
}

string Request::get_response_string()
{
    return mResponseString;
}

void Request::set_response_string(string response)
{
    mResponseString = response;
}

int Request::get_response_length()
{
    return mResponseString.size() + 1;
}

string Request::get_response_message()
{
    return mResponseMessage;
}

void Request::set_response_message(string message)
{
    mResponseMessage = message;
}

int Request::get_status_code()
{
    return mStatusCode;
}

void Request::set_status_code(int statusCode)
{
    mStatusCode = statusCode;
}

void Request::set_dump(string dump)
{
    mDump = dump;
}

string Request::get_dump()
{
    return mDump;
}

int Request::get_event_id()
{
    return mEventId;
}

void Request::set_event_id(int eventId)
{
    mEventId = eventId;
}