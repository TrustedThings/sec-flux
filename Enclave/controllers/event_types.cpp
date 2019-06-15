#include "event_types.h"
#include "../models/event_type.h"
#include "../request/http_responses.h"

void c_event_types_list(sqlite3 **db, Request *request)
{
    json_t *json = MEventType::get(db, 0, "");
    return http_success(request, json);
}

void c_event_types_create(sqlite3 **db, Request *request)
{
    MEventType eventType(db);
    if(!eventType.create_from_json_string(request->get_message().c_str())){
        return http_client_error(request);
    }
    request->set_status_code(201);
    request->set_backup(1);
    return http_created(request, eventType.to_json());
}

void c_event_types_read(sqlite3 **db, Request *request)
{
    int eventTypeId = stoi(request->get_path_parameter("eventTypeId"));
    MEventType eventType(db);
    eventType.set_id(eventTypeId);
    if(!eventType.get_by_id()) {
        return http_not_found(request);
    }
    return http_success(request, eventType.to_json());

}

void c_event_types_update(sqlite3 **db, Request *request)
{
    int eventTypeId = stoi(request->get_path_parameter("eventTypeId"));
    MEventType eventType(db);
    eventType.set_id(eventTypeId);
    if(!eventType.get_by_id()){
        return http_not_found(request);
    }
    if(!eventType.update_from_json_string(request->get_message().c_str())){
        return http_client_error(request);
    }
    request->set_backup(1);
    return http_success(request, eventType.to_json());
}

void c_event_types_delete(sqlite3 **db, Request *request)
{
    int eventTypeId = stoi(request->get_path_parameter("eventTypeId"));
    MEventType eventType(db);
    eventType.set_id(eventTypeId);
    if(!eventType.get_by_id()){
        return http_not_found(request);
    }
    eventType.delete_by_id();
    request->set_backup(1);
    return http_no_content(request);
}

void c_event_types_register(RequestManager *manager)
{
    Resource *resource;

    resource = new Resource();
    resource->set_path("/eventtypes/");
    resource->set_handler("GET", &c_event_types_list);
    resource->set_handler("POST", &c_event_types_create);
    manager->add_resource(resource);
    
    resource = new Resource();
    resource->set_path("/eventtypes/{eventTypeId}");
    resource->set_handler("GET", &c_event_types_read);
    resource->set_handler("PUT", &c_event_types_update);
    resource->set_handler("DELETE", &c_event_types_delete);
    manager->add_resource(resource);

}
