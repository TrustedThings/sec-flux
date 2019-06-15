#ifndef MODELS_ACTION_TYPE_H
#define MODELS_ACTION_TYPE_H

#include "object.h"

class MActionType: public MObject
{
  public:
    MActionType(sqlite3 **db);
    ~MActionType();

    static json_t *get_action_types(sqlite3 **db, int from, const char *orderBy);

    int save();
    int get_by_id();

    int validate();
    int create_from_json_string(const char *str);
    int update_from_json_string(const char *str);
    json_t *to_json();
    const char *to_string();

    unsigned char *get_name();
    unsigned char *get_schema();

    int set_name(unsigned char *name, bool copy);
    int set_schema(unsigned char *schema, bool copy);


  private:

    unsigned char *mName;
    unsigned char *mSchema;


};

#endif
