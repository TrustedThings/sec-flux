#ifndef CONTROLLERS_VERSIONS_H
#define CONTROLLERS_VERSIONS_H

#include "../database/sqlite3.h"
#include "../request/request.h"
#include "../request/request_manager.h"

void c_versions_read(sqlite3 **db, Request *request);

void c_versions_register(RequestManager *manager);

#endif