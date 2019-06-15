#ifndef MODELS_ACTION_MESSAGE_H
#define MODELS_ACTION_MESSAGE_H

#include <vector>
#include "object.h"

using namespace std;

class MActionMessage: public MObject
{
  public:
    MActionMessage(sqlite3 **db);
    ~MActionMessage();

    static vector<MActionMessage*> get_by_client_id(sqlite3 **db, int clientId, int from);

    // int get_by_event_id_rule_id_action_template_id();
    int save();

    int validate();

    int get_event_id();
    int get_rule_id();
    int get_action_template_id();
    unsigned char *get_message();
    unsigned char *get_timestamp();

    int set_event_id(int eventId);
    int set_rule_id(int ruleId);
    int set_action_template_id(int actionTemplateId);
    int set_message(unsigned char *message, bool copy);
    int set_timestamp(unsigned char *timestamp, bool copy);

  private:

    int mEventId;
    int mRuleId;
    int mActionTemplateId;
    unsigned char *mMessage;
    unsigned char *mTimestamp;

};

#endif
