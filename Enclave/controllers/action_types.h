#ifndef CONTROLLERS_ACTION_TYPES_H
#define CONTROLLERS_ACTION_TYPES_H

#include "../database/sqlite3.h"
#include "../request/request.h"
#include "../request/request_manager.h"

void c_action_types_list(sqlite3 **db, Request *request);
void c_action_types_create(sqlite3 **db, Request *request);

void c_action_types_read(sqlite3 **db, Request *request);
void c_action_types_update(sqlite3 **db, Request *request);
void c_action_types_delete(sqlite3 **db, Request *request);

void c_action_types_register(RequestManager *manager);

#endif