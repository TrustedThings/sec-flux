#include "rules.h"
#include "../models/rule.h"
#include "../request/http_responses.h"

void c_rules_list(sqlite3 **db, Request *request)
{
    json_t *json = MRule::get_rules(db, 0, "");
    return http_success(request, json);
}

void c_rules_create(sqlite3 **db, Request *request)
{
    MRule rule(db);
    if(!rule.create_from_json_string(request->get_message().c_str())){
        return http_client_error(request);
    }
    request->set_status_code(201);
    request->set_backup(1);
    return http_created(request, rule.to_json());
}

void c_rules_read(sqlite3 **db, Request *request)
{
    int ruleId = stoi(request->get_path_parameter("ruleId"));
    MRule rule(db);
    rule.set_id(ruleId);
    if(!rule.get_by_id()) {
        return http_not_found(request);
    }
    http_success(request, rule.to_json());
}

void c_rules_update(sqlite3 **db, Request *request)
{
    int ruleId = stoi(request->get_path_parameter("ruleId"));
    MRule rule(db);
    rule.set_id(ruleId);
    if(!rule.get_by_id()){
        return http_not_found(request);
    }
    if(!rule.update_from_json_string(request->get_message().c_str())){
        return http_client_error(request);
    }
    request->set_backup(1);
    return http_success(request, rule.to_json());
}

void c_rules_delete(sqlite3 **db, Request *request)
{
    int ruleId = stoi(request->get_path_parameter("ruleId"));
    MRule rule(db);
    rule.set_id(ruleId);
    if(!rule.get_by_id()){
        return http_not_found(request);
    }
    rule.delete_by_id();
    request->set_backup(1);
    return http_no_content(request);
}

void c_rules_register(RequestManager *manager)
{
    Resource *resource;

    resource = new Resource();
    resource->set_path("/rules/");
    resource->set_handler("GET", &c_rules_list);
    resource->set_handler("POST", &c_rules_create);
    manager->add_resource(resource);
    
    resource = new Resource();
    resource->set_path("/rules/{ruleId}");
    resource->set_handler("GET", &c_rules_read);
    resource->set_handler("PUT", &c_rules_update);
    resource->set_handler("DELETE", &c_rules_delete);
    manager->add_resource(resource);

}
