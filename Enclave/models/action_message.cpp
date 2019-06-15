#include "action_message.h"
#include "models.h"

MActionMessage::MActionMessage(sqlite3 **db): MObject(db)
{
  mTable = "action_messages";
  mMessage = NULL;
  mEventId = -1;
  mRuleId = -1;
  mActionTemplateId = -1;
  mTimestamp = NULL;
}


MActionMessage::~MActionMessage()
{
  if(mMessage != NULL) delete[] mMessage;
  if(mTimestamp != NULL) delete[] mTimestamp;
}

int MActionMessage::save()
{
  if(!mNew) return err("cannot update existing resource", error_misc);
  int res;
  if(!validate()){
    return 0;
  }
  const char *request = "INSERT INTO action_messages (event_id, rule_id, action_template_id, message, timestamp) VALUES (?, ?, ?, ?, ?);";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mEventId);
  sqlite3_bind_int(statement, 2, mRuleId);
  sqlite3_bind_int(statement, 3, mActionTemplateId);
  sqlite3_bind_text(statement, 4, (const char *)mMessage, -1, SQLITE_STATIC);
  sqlite3_bind_text(statement, 5, (const char *)mTimestamp, -1, SQLITE_STATIC);
  res = sqlite3_step(statement);
  sqlite3_finalize(statement);
  if(res != SQLITE_DONE) {
    return err("error saving action message", error_misc);
  }
  if(mNew) mId = sqlite3_last_insert_rowid(mDb);
  mNew = false;
  return 1;
}

vector<MActionMessage*> MActionMessage::get_by_client_id(sqlite3 **db, int clientId, int from)
{
    int ret;
    vector<MActionMessage*> actionMessages;
    const char *request = "SELECT id, event_id, rule_id, action_template_id, message, timestamp FROM action_messages WHERE action_template_id IN (SELECT action_template_id FROM action_template_clients WHERE client_id = ?);";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    sqlite3_bind_int(statement, 1, clientId);
    ret = sqlite3_step(statement);
    MActionMessage *actionMessage;
    while(ret == SQLITE_ROW) {
        actionMessage = new MActionMessage(db);
        actionMessage->set_id(sqlite3_column_int(statement, 0));
        actionMessage->set_event_id(sqlite3_column_int(statement, 1));
        actionMessage->set_rule_id(sqlite3_column_int(statement, 2));
        actionMessage->set_action_template_id(sqlite3_column_int(statement, 3));
        actionMessage->set_message((unsigned char *)sqlite3_column_text(statement, 4), true);
        actionMessage->set_timestamp((unsigned char *)sqlite3_column_text(statement, 5), true);
        actionMessages.push_back(actionMessage);
        ret = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    return actionMessages;
}
/**
int MActionMessage::get_by_event_id_rule_id_action_template_id()
{
  if(mEventId == -1 || mRuleId == -1 || mActionTemplateId == -1){
    return err("missing fields", error_misc);
  }
  int res;
  const char *request = "SELECT id, message FROM event_types WHERE event_id = ? AND rule_id = ? AND action_template_id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mEventId);
  sqlite3_bind_int(statement, 2, mRuleId);
  sqlite3_bind_int(statement, 3, mActionTemplateId);
  res = sqlite3_step(statement);
  if(res != SQLITE_ROW) {
    err("no action message found", error_misc);
    sqlite3_finalize(statement);
    return 0;
  }
  mId = sqlite3_column_int(statement, 0);
  set_text_field(statement, 1, &mMessage);

  sqlite3_finalize(statement);
  return 1;
}
**/

int MActionMessage::validate()
{
  // We assume the related resources exists since they have been processed prior to creating an action message
  if(mMessage == NULL ){
    return err("missing message", error_misc);
  }
  if(mTimestamp == NULL) {
    return err("missing timestamp", error_misc);
  }
  if(mEventId == -1) return err("missing event id", error_misc);
  if(mRuleId == -1) return err("missing rule id", error_misc);
  if(mActionTemplateId == -1) return err("missing action template id", error_misc);
  
  return 1;
}

int MActionMessage::get_event_id()
{
    return mEventId;
}

int MActionMessage::get_rule_id()
{
    return mRuleId;
}

int MActionMessage::get_action_template_id()
{
    return mActionTemplateId;
}

unsigned char *MActionMessage::get_message()
{
    return mMessage;
}

unsigned char *MActionMessage::get_timestamp()
{
    return mTimestamp;
}

int MActionMessage::set_event_id(int eventId)
{
    mEventId = eventId;
}

int MActionMessage::set_rule_id(int ruleId)
{
    mRuleId = ruleId;
}

int MActionMessage::set_action_template_id(int actionTemplateId)
{
    mActionTemplateId = actionTemplateId;
}

int MActionMessage::set_message(unsigned char *message, bool copy)
{
    return set_text_field(message, &mMessage, copy);
}

int MActionMessage::set_timestamp(unsigned char *timestamp, bool copy)
{
    return set_text_field(timestamp, &mTimestamp, copy);
}