#ifndef MODELS_ACTION_TEMPLATE_CLIENT_H
#define MODELS_ACTION_TEMPLATE_CLIENT_H

#include <vector>
#include "../database/sqlite3.h"
#include <jansson.h>

using namespace std;

class MActionTemplateClient
{
  public:

    static int create_by_action_template_id(sqlite3 **db, int actionTemplateId, json_t *clients);
    static json_t *get_by_action_template_id(sqlite3 **db, int actionTemplateId);
    static int update_by_action_template_id(sqlite3 **db, int actionTemplateId, json_t *clients);
    static int delete_by_action_template_id(sqlite3 **db, int actionTemplateId);

  private:

};

#endif
