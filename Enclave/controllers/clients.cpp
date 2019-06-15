#include "clients.h"
#include "../models/client.h"
#include "../models/action_message.h"
#include "../request/http_responses.h"

void c_clients_list(sqlite3 **db, Request *request)
{
    json_t *json = MClient::get_clients(db, 0, "");
    return http_success(request, json);
}

void c_clients_create(sqlite3 **db, Request *request)
{
    MClient client(db);
    if(!client.create_from_json_string(request->get_message().c_str())){
        return http_client_error(request);
    }
    request->set_status_code(201);
    request->set_backup(1);
    return http_created(request, client.to_json());
}

void c_clients_read(sqlite3 **db, Request *request)
{
    int clientId = stoi(request->get_path_parameter("clientId"));
    MClient client(db);
    client.set_id(clientId);
    if(!client.get_by_id()) {
        return http_not_found(request);
    }
    http_success(request, client.to_json());
}

void c_clients_update(sqlite3 **db, Request *request)
{
    int clientId = stoi(request->get_path_parameter("clientId"));
    MClient client(db);
    client.set_id(clientId);
    if(!client.get_by_id()){
        return http_not_found(request);
    }
    if(!client.update_from_json_string(request->get_message().c_str())){
        return http_client_error(request);
    }
    request->set_backup(1);
    return http_success(request, client.to_json());
}

void c_clients_delete(sqlite3 **db, Request *request)
{
    int clientId = stoi(request->get_path_parameter("clientId"));
    MClient client(db);
    client.set_id(clientId);
    if(!client.get_by_id()){
        return http_not_found(request);
    }
    client.delete_by_id();
    request->set_backup(1);
    return http_no_content(request);
}

void c_clients_list_actions(sqlite3 **db, Request *request)
{
    json_t *actions = json_array();
    json_t *action;
    int clientId = stoi(request->get_path_parameter("clientId"));
    vector<MActionMessage*> actionMessages = MActionMessage::get_by_client_id(db, clientId, 0);
    MActionMessage *actionMessage;
    for(int i = 0; i < actionMessages.size(); i++) {
        actionMessage = actionMessages[i];
        json_t *message = json_loads((const char *)actionMessage->get_message(), 0, NULL);
        action = json_pack("{s:i,s:i,s:i,s:i,s:o,s:s}",
            "id", 1000000 * actionMessage->get_id() + clientId,
            "clientId", clientId,
            "eventId", actionMessage->get_event_id(),
            "actionTemplateId", actionMessage->get_action_template_id(),
            "message", message,
            "timestamp", actionMessage->get_timestamp()
        );

        json_array_append_new(actions, action);

        delete actionMessage;
    }
    return http_success(request, actions);
}

void c_clients_read_action(sqlite3 **db, Request *request)
{

}

void c_clients_register(RequestManager *manager)
{
    Resource *resource;

    resource = new Resource();
    resource->set_path("/clients/");
    resource->set_handler("GET", &c_clients_list);
    resource->set_handler("POST", &c_clients_create);
    manager->add_resource(resource);
    
    resource = new Resource();
    resource->set_path("/clients/{clientId}");
    resource->set_handler("GET", &c_clients_read);
    resource->set_handler("PUT", &c_clients_update);
    resource->set_handler("DELETE", &c_clients_delete);
    manager->add_resource(resource);

    resource = new Resource();
    resource->set_path("/clients/{clientId}/actions/");
    resource->set_handler("GET", &c_clients_list_actions);
    manager->add_resource(resource);

    resource = new Resource();
    resource->set_path("/clients/{clientId}/actions/{actionId}");
    resource->set_handler("GET", &c_clients_read_action);
    manager->add_resource(resource);

}
