#ifndef CONTROLLERS_RULES_H
#define CONTROLLERS_RULES_H

#include "../database/sqlite3.h"
#include "../request/request.h"
#include "../request/request_manager.h"

void c_rules_list(sqlite3 **db, Request *request);
void c_rules_create(sqlite3 **db, Request *request);

void c_rules_read(sqlite3 **db, Request *request);
void c_rules_update(sqlite3 **db, Request *request);
void c_rules_delete(sqlite3 **db, Request *request);

void c_rules_register(RequestManager *manager);

#endif