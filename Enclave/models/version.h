#ifndef MODELS_VERSION_H
#define MODELS_VERSION_H

#include "../database/sqlite3.h"
#include "../json.h"

class MVersion
{
  public:

    void get(sqlite3 **db);
    json_t *to_json();

  private:
    int mVersion;
};

#endif
