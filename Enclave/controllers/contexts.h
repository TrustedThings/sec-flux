#ifndef CONTROLLERS_CONTEXTS_H
#define CONTROLLERS_CONTEXTS_H

#include "../database/sqlite3.h"
#include "../request/request.h"
#include "../request/request_manager.h"

void c_contexts_eval_create(sqlite3 **db, Request *request);

void c_contexts_register(RequestManager *manager);

#endif