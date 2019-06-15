#ifndef MODELS_URL_H
#define MODELS_URL_H

#include "object.h"

class MUrl: public MObject
{
  public:
    MUrl(sqlite3 **db);
    ~MUrl();

    int save();
    int get_by_id();
    
    int validate();
    int create_from_json_string(const char *str);
    int update_from_json_string(const char *str);
    json_t *to_json();

    unsigned char *get_value();

    int set_value(unsigned char *value, bool copy);


  private:
    unsigned char *mValue;


};

#endif
