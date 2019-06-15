#ifndef CONTROLLERS_EVENT_TYPES_H
#define CONTROLLERS_EVENT_TYPES_H

#include "../database/sqlite3.h"
#include "../request/request.h"
#include "../request/request_manager.h"

void c_event_types_list(sqlite3 **db, Request *request);
void c_event_types_create(sqlite3 **db, Request *request);

void c_event_types_read(sqlite3 **db, Request *request);
void c_event_types_update(sqlite3 **db, Request *request);
void c_event_types_delete(sqlite3 **db, Request *request);

void c_event_types_register(RequestManager *manager);

#endif