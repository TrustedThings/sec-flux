#ifndef MODELS_ACTION_TEMPLATE_H
#define MODELS_ACTION_TEMPLATE_H

#include "object.h"
#include <vector>

using namespace std;

class MActionTemplate: public MObject
{
  public:
    MActionTemplate(sqlite3 **db);
    ~MActionTemplate();

    static json_t *get(sqlite3 **db, int from, const char *orderBy);

    static vector<MActionTemplate*> get_by_rule_id(sqlite3 **db, int ruleId);

    int save();
    int get_by_id();

    int validate();
    int create_from_json(json_t *json);
    int update_from_json(json_t *json, bool write);
    json_t *to_json();
    const char *to_string();

    unsigned char *get_name();
    int get_rule_id();
    int get_action_type_id();
    unsigned char *get_function();
    unsigned char *get_context(bool copy);

    int set_name(unsigned char *name, bool copy);
    int set_rule_id(int ruleId);
    int set_action_type_id(int actionTypeId);
    int set_function(unsigned char *function, bool copy);
    int set_context(unsigned char *context, bool copy);

  private:

    unsigned char *mName;
    int mRuleId;
    int mActionTypeId;
    unsigned char *mFunction;
    unsigned char *mContext;

};

#endif
