#ifndef MODELS_CONTEXT_H
#define MODELS_CONTEXT_H

#include "../database/sqlite3.h"

class MContext
{
  public:

    static char *get_context(sqlite3 **db);
    static int set_context(sqlite3 **db, const char *context);

};

#endif
