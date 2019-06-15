#include "controller.h"
#include "action_templates.h"
#include "action_types.h"
#include "clients.h"
#include "contexts.h"
#include "events.h"
#include "event_types.h"
#include "rules.h"
#include "versions.h"

void register_controllers(RequestManager *manager)
{
    c_action_templates_register(manager);
    c_action_types_register(manager);
    c_clients_register(manager);
    c_contexts_register(manager);
    c_events_register(manager);
    c_event_types_register(manager);
    c_rules_register(manager);
    c_versions_register(manager);
}