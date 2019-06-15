#ifndef MODELS_EVENT_TYPE_H
#define MODELS_EVENT_TYPE_H

#include "object.h"

class MEventType: public MObject
{
  public:
    MEventType(sqlite3 **db);
    ~MEventType();

    static json_t *get(sqlite3 **db, int from, const char *orderBy);

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
