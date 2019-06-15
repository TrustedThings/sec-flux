#ifndef CONTROLLERS_CLIENTS_H
#define CONTROLLERS_CLIENTS_H

#include "../database/sqlite3.h"
#include "../request/request.h"
#include "../request/request_manager.h"

void c_clients_list(sqlite3 **db, Request *request);
void c_clients_create(sqlite3 **db, Request *request);

void c_clients_read(sqlite3 **db, Request *request);
void c_clients_update(sqlite3 **db, Request *request);
void c_clients_delete(sqlite3 **db, Request *request);

void c_clients_list_actions(sqlite3 **db, Request *request);
void c_clients_read_action(sqlite3 **db, Request *request);

void c_clients_register(RequestManager *manager);

#endif