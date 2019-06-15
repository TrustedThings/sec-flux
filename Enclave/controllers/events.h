#ifndef CONTROLLERS_EVENTS_H
#define CONTROLLERS_EVENTS_H

#include "../database/sqlite3.h"
#include "../request/request.h"
#include "../request/request_manager.h"

void c_events_list(sqlite3 **db, Request *request);
void c_events_create(sqlite3 **db, Request *request);

void c_events_read(sqlite3 **db, Request *request);
void c_events_delete(sqlite3 **db, Request *request);

void c_events_register(RequestManager *manager);

#endif