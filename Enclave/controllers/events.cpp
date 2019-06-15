#include "events.h"
#include "../models/context.h"
#include "../models/event.h"
#include "../models/rule.h"
#include "../models/action_message.h"
#include "../models/action_template.h"
#include "../request/http_responses.h"
#include "../my_duk.h"

using namespace std;

static duk_ret_t native_bool(duk_context *ctx) {

}

void c_events_list(sqlite3 **db, Request *request)
{
    map<string, string> params = request->get_query_parameters();
    json_t *json = MEvent::get_events(db, params);
    return http_success(request, json);
}

void c_events_create(sqlite3 **db, Request *request)
{
    MEvent event(db);
    if(!event.create_from_json_string(request->get_message().c_str())){
        return http_client_error(request);
    }
    // Create backup structure
    string properties = (char *)event.get_properties();
    string timestamp = (char *)event.get_timestamp();
    string backup;
    backup = "INSERT INTO \"events\" VALUES(" 
        + to_string(event.get_id()) + ","
        + to_string(event.get_client_id()) + ","
        + to_string(event.get_event_type_id()) + ","
        + "'" + properties + "','" + timestamp + "');\n";

    /** 
     * Trigger rules and actions if needed 
    */

    // Retrieve global context
    char *globalContext = MContext::get_context(db);

    // Fetch associated rules 
    vector<MRule*> rules = MRule::get_by_event_type_id(db, event.get_event_type_id());
    MRule *rule;
    unsigned char *ruleContext;
    // evaluate rules
    bool res;
    for(int i = 0; i < rules.size(); i++) {
        rule = rules[i];
        ruleContext = rule->get_context(true);

        res = duk_eval_rule(
            (const char *)rule->get_function(),
            (const char *)event.get_properties(),
            (char **)&ruleContext,
            &globalContext
        );
        // Save local context
        rule->set_context((unsigned char *)ruleContext, false);
        rule->save();
        if(res == 1) {
            // Retrieve action templates
            vector<MActionTemplate*> actionTemplates = MActionTemplate::get_by_rule_id(db, rule->get_id());
            MActionTemplate *actionTemplate;
            unsigned char *localContext;

            for(int j = 0; j < actionTemplates.size(); j++) {

                // Evaluate action template script
                actionTemplate = actionTemplates[j];
                localContext = actionTemplate->get_context(true);

                char *message = duk_eval_template(
                    (const char *)actionTemplate->get_function(), 
                    (const char *)event.get_properties(),
                    (char **)&localContext,
                    &globalContext
                );
                // Check validity
                if(message == NULL) {
                    delete[] localContext;
                } else {
                    // Save local context
                    actionTemplate->set_context((unsigned char *)localContext, false);
                    // TODO: check save
                    actionTemplate->save();

                    // Create action message
                    MActionMessage actionMessage(db);
                    actionMessage.set_event_id(event.get_id());
                    actionMessage.set_rule_id(rule->get_id());
                    actionMessage.set_action_template_id(actionTemplate->get_id());
                    actionMessage.set_message((unsigned char *)message, false);
                    actionMessage.set_timestamp(event.get_timestamp(), true);
                    if(!actionMessage.save()) {
                        printf("Could not save action message!\n");
                    }
                    // Backup action message
                    string message = (char *)actionMessage.get_message();
                    backup += "INSERT INTO \"action_messages\" VALUES("
                        + to_string(actionMessage.get_id()) + ","
                        + "'" + message + "','" + timestamp + "',"
                        + to_string(actionMessage.get_action_template_id()) + ","
                        + to_string(actionMessage.get_event_id()) + ","
                        + to_string(actionMessage.get_rule_id()) + ");\n";
                }
            }
        }
        // TODO: save rule context
        delete rule;
    }
    // Save global context
    MContext::set_context(db, (const char *)globalContext);
    delete[] globalContext;

    // backup event and action message
    request->set_backup(2);
    request->set_dump(backup);
    request->set_event_id(event.get_id());
    return http_created(request, event.to_json());
}

void c_events_read(sqlite3 **db, Request *request)
{
    int eventId = stoi(request->get_path_parameter("eventId"));
    MEvent event(db);
    event.set_id(eventId);
    if(!event.get_by_id()) {
        return http_not_found(request);
    }
    http_success(request, event.to_json());
}

void c_events_delete(sqlite3 **db, Request *request)
{
    int eventId = stoi(request->get_path_parameter("eventId"));
    MEvent event(db);
    event.set_id(eventId);
    if(!event.get_by_id()){
        return http_not_found(request);
    }
    event.delete_by_id();
    return http_no_content(request);
}

void c_events_register(RequestManager *manager)
{
    Resource *resource;

    resource = new Resource();
    resource->set_path("/events/");
    resource->set_handler("GET", &c_events_list);
    resource->set_handler("POST", &c_events_create);
    manager->add_resource(resource);
    
    resource = new Resource();
    resource->set_path("/events/{eventId}");
    resource->set_handler("GET", &c_events_read);
    resource->set_handler("DELETE", &c_events_delete);
    manager->add_resource(resource);

}
