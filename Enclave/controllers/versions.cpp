#include "versions.h"
#include "../models/version.h"
#include "../request/http_responses.h"

void c_versions_read(sqlite3 **db, Request *request)
{
    MVersion version;
    version.get(db);
    http_success(request, version.to_json());
}

void c_versions_register(RequestManager *manager)
{
    Resource *resource;

    resource = new Resource();
    resource->set_path("/version");
    resource->set_handler("GET", &c_versions_read);
    manager->add_resource(resource);
}
