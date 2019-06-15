#include "request_manager.h"
#include "http_responses.h"
#include "../controllers/controller.h"
// DEBUG
#include "../models/client.h"
#include <algorithm>
#include <cmath>

RequestManager::RequestManager()
{
    mRequest = NULL;

    // Register all handlers (resources)
    register_controllers(this);

    // Sort resources by access priority
    std::sort(mResources.begin(), mResources.end(), resource_compare);
    /**
    for(vector<Resource*>::iterator it=mResources.begin(); it!=mResources.end(); ++it){
        printf("resource path: %s\n", (*it)->get_path().c_str());
    }
    **/
}

RequestManager::~RequestManager()
{
    if(mRequest != NULL) delete mRequest;
}

int RequestManager::init(sqlite3 **ptr)
{
    mDb = ptr;

    // Register admin
    /*
    MClient *mClient = new MClient(mDb);
    int ret = mClient->create_from_json_string("{\"name\": \"Pascal\", \"pubKey\": {\"crv\":\"P-256\",\"ext\":true,\"key_ops\":[\"verify\"],\"kty\":\"EC\",\"x\": \"F0A1007081A7793C65DDC7031C85091783D0E764AF4B67B043B5976618F70EE9\", \"y\": \"B2083257B4CA1CD304063F1C57D23C302C4B3BB7D217DFA6BCA955B275DA453B\"}, \"isActive\": true, \"isAdmin\": true}");
    delete mClient;
    return 1;
    */
}

void RequestManager::set_request(Request *request)
{
    if(mRequest != NULL) delete mRequest;
    mRequest = request;
}

int RequestManager::do_request(int *backup)
{
    // Find handler
    for(vector<Resource*>::iterator it = mResources.begin(); it != mResources.end(); it++){
        if((*it)->match(mRequest)) {
            (*it)->handle(mDb, mRequest);
            *backup = mRequest->get_backup();
            return 1;
        }
    }
    http_not_found(mRequest);

    return 0;
}

Request *RequestManager::get_request()
{
    return mRequest;
}

int RequestManager::get_response_length()
{
    return mRequest->get_response_length();
}

void RequestManager::add_resource(Resource *resource)
{
    mResources.push_back(resource);
}

bool RequestManager::resource_compare(Resource *i, Resource *j)
{
    return resource_priority(i) < resource_priority(j);
}

int RequestManager::resource_priority(Resource *resource)
{
    string path = resource->get_path();
    string delimiter = "/";
    int index = 0;
    int priority = 0;
    int pos = 0;

    while(true)
    {
        pos = path.find(delimiter);
        if(path.rfind("{", 0) == 0) {
            priority += pow(2, index);
        }
        if(pos == string::npos) break;
        path.erase(0, pos + delimiter.length());
        index += 1;
    }
    return priority;
}

sqlite3 **RequestManager::get_db_ptr()
{
    return mDb;
}
