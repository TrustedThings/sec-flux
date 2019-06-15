#ifndef CONTROLLERS_ACTION_TEMPALTES_H
#define CONTROLLERS_ACTION_TEMPLATES_H

#include "../database/sqlite3.h"
#include "../request/request.h"
#include "../request/request_manager.h"

void c_action_templates_list(sqlite3 **db, Request *request);
void c_action_templates_create(sqlite3 **db, Request *request);

void c_action_templates_read(sqlite3 **db, Request *request);
void c_action_templates_update(sqlite3 **db, Request *request);
void c_action_templates_delete(sqlite3 **db, Request *request);

void c_action_templates_register(RequestManager *manager);

#endif