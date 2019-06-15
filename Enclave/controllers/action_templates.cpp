#include "action_templates.h"
#include "../models/action_template.h"
#include "../models/action_template_client.h"
#include "../request/http_responses.h"

void c_action_templates_list(sqlite3 **db, Request *request)
{
    json_t *json = MActionTemplate::get(db, 0, "");
    int id;
    for (int i = 0; i < json_array_size(json); i++) {
        json_t *actionTemplate = json_array_get(json, i);
        id = json_integer_value(json_object_get(actionTemplate, "id"));
        json_t *clients = MActionTemplateClient::get_by_action_template_id(db, id);
        json_object_set_new(actionTemplate, "clients", clients);
    }
    return http_success(request, json);
}

void c_action_templates_create(sqlite3 **db, Request *request)
{
    int ret;
    json_error_t error;
    json_auto_t *json = json_loads(request->get_message().c_str(), 0, &error);
    if(json == NULL) {
        return http_client_error(request);
    }
    // Extract clients
    json_t *temp = json_object_get(json, "clients");
    if(temp == NULL){
        return http_client_error(request);
    }
    // Copy clients to remove them from the action template
    json_auto_t *clients = json_deep_copy(temp);
    json_object_del(json, "clients");
    
    // Create action template
    MActionTemplate actionTemplate(db);
    if(!actionTemplate.create_from_json(json)) {
        return http_client_error(request);
    }
    actionTemplate.set_id(sqlite3_last_insert_rowid(*db));

    // Create associated clients
    if(!MActionTemplateClient::create_by_action_template_id(db, actionTemplate.get_id(), clients)) {
        actionTemplate.delete_by_id();
        return http_client_error(request);
    }

    json_t *jsonRes = actionTemplate.to_json();
    json_t *resClients = json_deep_copy(clients);
    json_object_set_new(jsonRes, "clients", resClients);
    request->set_backup(1);

    return http_created(request, jsonRes);
}

void c_action_templates_read(sqlite3 **db, Request *request)
{
    int actionTemplateId = stoi(request->get_path_parameter("actionTemplateId"));
    // Get action template
    MActionTemplate actionTemplate(db);
    actionTemplate.set_id(actionTemplateId);
    if(!actionTemplate.get_by_id()) {
        return http_not_found(request);
    }
    json_t *json = actionTemplate.to_json();
    // Get associated clients
    json_t *clients = MActionTemplateClient::get_by_action_template_id(db, actionTemplate.get_id());
    json_object_set_new(json, "clients", clients);

    return http_success(request, json);

}

void c_action_templates_update(sqlite3 **db, Request *request)
{
    int ret;
    // Retrieve action template
    int actionTemplateId = stoi(request->get_path_parameter("actionTemplateId"));
    MActionTemplate actionTemplate(db);
    actionTemplate.set_id(actionTemplateId);
    if(!actionTemplate.get_by_id()){
        return http_not_found(request);
    }
    json_error_t error;
    json_t *json = json_loads(request->get_message().c_str(), 0, &error);
    if(json == NULL) {
        return http_client_error(request);
    }
    // Extract clients
    json_t *temp = json_object_get(json, "clients");
    if(temp == NULL) {
        return http_client_error(request);
    }
    json_auto_t *clients = json_deep_copy(temp);
    json_object_del(json, "clients");

    // Validate action template
    if(!actionTemplate.update_from_json(json, false)){
        return http_client_error(request);
    }

    // Update associated clients
    if(!MActionTemplateClient::update_by_action_template_id(db, actionTemplateId, clients)) {
        return http_client_error(request);
    }

    // Update action template
    if(!actionTemplate.update_from_json(json, true)) {
        return http_server_error(request);
        printf("Action template update failed after successful validation!\n");
    }
    json_t *jsonRes = actionTemplate.to_json();
    json_t *resClients = json_deep_copy(clients);
    json_object_set_new(jsonRes, "clients", resClients);
    request->set_backup(1);

    return http_success(request, jsonRes);
}

void c_action_templates_delete(sqlite3 **db, Request *request)
{
    int actionTemplateId = stoi(request->get_path_parameter("actionTemplateId"));
    MActionTemplate actionTemplate(db);
    actionTemplate.set_id(actionTemplateId);
    if(!actionTemplate.get_by_id()){
        return http_not_found(request);
    }
    int ret = actionTemplate.delete_by_id();
    if(ret != 1) {
        printf("could not delete existing action template!\n");
    }
    ret = MActionTemplateClient::delete_by_action_template_id(db, actionTemplateId);
    if(ret != 1) {
        printf("could not delete clietns from action template!\n");
    }
    request->set_backup(1);
    return http_no_content(request);
}

void c_action_templates_register(RequestManager *manager)
{
    Resource *resource;

    resource = new Resource();
    resource->set_path("/actiontemplates/");
    resource->set_handler("GET", &c_action_templates_list);
    resource->set_handler("POST", &c_action_templates_create);
    manager->add_resource(resource);
    
    resource = new Resource();
    resource->set_path("/actiontemplates/{actionTemplateId}");
    resource->set_handler("GET", &c_action_templates_read);
    resource->set_handler("PUT", &c_action_templates_update);
    resource->set_handler("DELETE", &c_action_templates_delete);
    manager->add_resource(resource);

}
