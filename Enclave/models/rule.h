#ifndef MODELS_RULE_H
#define MODELS_RULE_H

#include "object.h"

class MRule: public MObject
{
  public:
    MRule(sqlite3 **db);
    ~MRule();

    static json_t *get_rules(sqlite3 **db, int from, const char *orderBy);
    static std::vector<MRule*> get_by_event_type_id(sqlite3 **db, int eventTypeId);

    int save();
    int get_by_id();

    int validate();
    int create_from_json_string(const char *str);
    int update_from_json_string(const char *str);
    json_t *to_json();

    unsigned char *get_name();
    unsigned char *get_function();
    unsigned char *get_context(bool copy);
    int get_event_type_id();
    int get_is_active();

    int set_name(unsigned char *name, bool copy);
    int set_function(unsigned char *function, bool copy);
    int set_context(unsigned char *context, bool copy);
    int set_event_type_id(int eventTypeId);
    int set_is_active(int is_active);

  private:

    unsigned char *mName;
    unsigned char *mFunction;
    unsigned char *mContext;
    int mEventTypeId;
    int mIsActive;

};

#endif
