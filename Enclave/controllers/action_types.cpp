#include "action_types.h"
#include "../models/action_type.h"
#include "../request/http_responses.h"

void c_action_types_list(sqlite3 **db, Request *request)
{
    json_t *json = MActionType::get_action_types(db, 0, "");
    return http_success(request, json);
}

void c_action_types_create(sqlite3 **db, Request *request)
{
    MActionType actionType(db);
    if(!actionType.create_from_json_string(request->get_message().c_str())){
        return http_client_error(request);
    }
    request->set_backup(1);
    return http_created(request, actionType.to_json());
}

void c_action_types_read(sqlite3 **db, Request *request)
{
    int actionTypeId = stoi(request->get_path_parameter("actionTypeId"));
    MActionType actionType(db);
    actionType.set_id(actionTypeId);
    if(!actionType.get_by_id()) {
        return http_not_found(request);
    }
    return http_success(request, actionType.to_json());

}

void c_action_types_update(sqlite3 **db, Request *request)
{
    int actionTypeId = stoi(request->get_path_parameter("actionTypeId"));
    MActionType actionType(db);
    actionType.set_id(actionTypeId);
    if(!actionType.get_by_id()){
        return http_not_found(request);
    }
    if(!actionType.update_from_json_string(request->get_message().c_str())){
        return http_client_error(request);
    }
    request->set_backup(1);
    return http_success(request, actionType.to_json());
}

void c_action_types_delete(sqlite3 **db, Request *request)
{
    int actionTypeId = stoi(request->get_path_parameter("actionTypeId"));
    MActionType actionType(db);
    actionType.set_id(actionTypeId);
    if(!actionType.get_by_id()){
        return http_not_found(request);
    }
    actionType.delete_by_id();
    request->set_backup(1);
    return http_no_content(request);
}

void c_action_types_register(RequestManager *manager)
{
    Resource *resource;

    resource = new Resource();
    resource->set_path("/actiontypes/");
    resource->set_handler("GET", &c_action_types_list);
    resource->set_handler("POST", &c_action_types_create);
    manager->add_resource(resource);
    
    resource = new Resource();
    resource->set_path("/actiontypes/{actionTypeId}");
    resource->set_handler("GET", &c_action_types_read);
    resource->set_handler("PUT", &c_action_types_update);
    resource->set_handler("DELETE", &c_action_types_delete);
    manager->add_resource(resource);

}
