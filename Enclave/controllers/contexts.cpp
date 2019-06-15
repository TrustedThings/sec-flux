#include "contexts.h"
#include "../models/context.h"
#include "../request/http_responses.h"
#include "../my_duk.h"

void c_contexts_eval_create(sqlite3 **db, Request *request)
{
    int ret;
    const char *function;
    json_auto_t *json;
    json_error_t error;
    // Extract json
    json = json_loads(request->get_message().c_str(), 0, &error);
    if(json == NULL) return http_client_error(request);
    ret = json_unpack_ex(json, &error, JSON_STRICT, "{s:s}", 
        "function", &function    
    );
    if(ret != 0) return http_client_error(request);

    char *context = MContext::get_context(db);
    // Evaluate function
    ret = duk_eval_global_context(function, &context);
    if(!ret) {
        delete[] context;
        return http_client_error(request);
    }

    MContext::set_context(db, context);
    delete[] context;
    request->set_backup(1);
    return http_no_content(request);
}

void c_contexts_register(RequestManager *manager)
{
    Resource *resource;

    resource = new Resource();
    resource->set_path("/context/eval");
    resource->set_handler("POST", &c_contexts_eval_create);
    manager->add_resource(resource);
}
