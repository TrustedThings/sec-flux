#include "rule.h"
#include "event_type.h"

using namespace std;

MRule::MRule(sqlite3 **db): MObject(db)
{
  mTable = "rules";

  mName = NULL;
  mFunction = NULL;
  mContext = NULL;
  mEventTypeId = -1;
  mIsActive = -1;
}


MRule::~MRule()
{
  if(mName == NULL) delete[] mName;
  if(mFunction != NULL) delete[] mFunction;
  if(mContext != NULL) delete[] mContext;
}

json_t *MRule::get_rules(sqlite3 **db, int from, const char *orderBy)
{
    int res;
    json_t *json = json_array();

    const char *request = "SELECT id, name, function, context, event_type_id, is_active FROM rules";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    res = sqlite3_step(statement);

    while(res == SQLITE_ROW){
        json_t *rule = json_pack("{s:i,s:s,s:s,s:s,s:i,s:b}",
            "id", sqlite3_column_int(statement, 0),
            "name", sqlite3_column_text(statement, 1),
            "function", sqlite3_column_text(statement, 2),
            "context", sqlite3_column_text(statement, 3),
            "eventTypeId", sqlite3_column_int(statement, 4),
            "isActive", sqlite3_column_int(statement, 5)
        );
        json_array_append_new(json, rule);
        res = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    return json;
}

vector<MRule*> MRule::get_by_event_type_id(sqlite3 **db, int eventTypeId)
{
    int res;
    vector<MRule*> rules;
    const char *request = "SELECT id, is_active, name, function, context FROM rules WHERE event_type_id = ? AND is_active = 1;";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    sqlite3_bind_int(statement, 1, eventTypeId);
    res = sqlite3_step(statement);

    while(res == SQLITE_ROW) {
        MRule *rule = new MRule(db);
        unsigned char *name = NULL;
        unsigned char *function = NULL;
        unsigned char *context = NULL;
        
        rule->set_id(sqlite3_column_int(statement, 0));
        rule->set_is_active(sqlite3_column_int(statement, 1));
        rule->set_text_field(statement, 2, &name);
        rule->set_name(name, false);
        rule->set_text_field(statement, 3, &function);
        rule->set_function(function, false);
        rule->set_text_field(statement, 4, &context);
        rule->set_context(context, false);
        rule->set_event_type_id(eventTypeId);
        rules.push_back(rule);
        res = sqlite3_step(statement);
        
    }
    sqlite3_finalize(statement);

    return rules;
}

int MRule::save()
{
  int res;
  
  if(!validate()){
    return err("missing fields", error_misc);
  }
  // Save rule
  const char *request = mNew 
    ? "INSERT INTO rules (name, function, event_type_id, is_active, context) VALUES (?, ?, ?, ?, ?);"
    : "UPDATE rules SET name = ?, function = ?, event_type_id = ?, is_active = ?, context = ? WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_text(statement, 1, (const char *)mName, -1, SQLITE_STATIC);
  sqlite3_bind_text(statement, 2, (const char *)mFunction, -1, SQLITE_STATIC);
  sqlite3_bind_int(statement, 3, mEventTypeId);
  sqlite3_bind_int(statement, 4, mIsActive);
  sqlite3_bind_text(statement, 5, (const char *)mContext, -1, SQLITE_STATIC);
  if(!mNew) sqlite3_bind_int(statement, 6, mId);
  res = sqlite3_step(statement);
  sqlite3_finalize(statement);
  if(res != SQLITE_DONE) {
    return err("error saving rule", error_misc);
  }
  if(mNew) mId = sqlite3_last_insert_rowid(mDb);
  mNew = false;

  return 1;
}

int MRule::get_by_id()
{
  if(mNew){
    return err("missing id", error_misc);
  }
  int res;

  // Fetch rule
  const char *request = "SELECT name, function, event_type_id, is_active, context FROM rules WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mId);
  res = sqlite3_step(statement);
  if(res != SQLITE_ROW) {
    err("no rule found", error_misc);
    sqlite3_finalize(statement);
    return 0;
  }
  set_text_field(statement, 0, &mName);
  set_text_field(statement, 1, &mFunction);
  mEventTypeId = sqlite3_column_int(statement, 2);
  mIsActive = sqlite3_column_int(statement, 3);
  set_text_field(statement, 4, &mContext);
  sqlite3_finalize(statement);

  return 1;
}

int MRule::validate()
{
    // name
    if(mName == NULL || strlen((const char *)mName) == 0){
        return err("name empty", error_misc);
    }
    // function
    if(mFunction == NULL || strlen((const char *)mFunction) == 0){
        return err("function empty", error_misc);
    }
    // context
    if(mContext == NULL || strlen((const char *)mContext) == 0){
        return err("context empty", error_misc);
    }
    // event type id
    if(mEventTypeId < 0) return err("missing event type id", error_misc);
    MEventType eventType(&mDb);
    if(eventType.check_exists(mEventTypeId) != 1) return err("event type not found", error_misc);
    // is active
    if(mIsActive < 0) return err("isActive property missing", error_misc);
    return 1;
}

int MRule::create_from_json_string(const char *str)
{
    int ret;
    json_auto_t *json;
    json_error_t jsonError;
    const char *name, *function, *context;

    // Extract json
    json = json_loads(str, 0, &jsonError);
    if(json == NULL) return err("no valid json", error_misc);
    ret = json_unpack_ex(json, &jsonError, JSON_STRICT, "{s:s,s:s,s:s,s:i,s:b}",
        "name", &name,
        "function", &function,
        "context", &context,
        "eventTypeId", &mEventTypeId,
        "isActive", &mIsActive
    );
    if(ret != 0) return err("malformed json", error_misc);
    set_name((unsigned char *)name, true);
    set_function((unsigned char *)function, true);
    set_context((unsigned char *)context, true);
    if(validate() != 1) return 0;
    if(save() != 1) {
        printf("error saving rule!");
        return 0;
    }
    return 1;
}

int MRule::update_from_json_string(const char *str)
{
    if(mNew || get_by_id() != 1) return err("no rule", error_misc);
    int ret;
    json_auto_t *json;
    json_error_t jsonError;
    const char *name, *function, *context;

    // Extract json
    json = json_loads(str, 0, &jsonError);
    ret = json_unpack_ex(json, &jsonError, JSON_STRICT, "{s:s,s:s,s:s,s:i,s:b}",
        "name", &name,
        "function", &function,
        "context", &context,
        "eventTypeId", &mEventTypeId,
        "isActive", &mIsActive
    );
    if(ret != 0) return err("malformed json", error_misc);
    set_name((unsigned char *)name, true);
    set_function((unsigned char *)function, true);
    set_context((unsigned char *)context, true);
    if(validate() != 1) return 0;
    if(save() != 1) {
        printf("error saving rule!");
        return 0;
    }
    return 1;
}

json_t *MRule::to_json()
{
    return json_pack("{s:i,s:s,s:s,s:s,s:i,s:b}",
        "id", mId,
        "name", mName,
        "function", mFunction,
        "context", mContext,
        "eventTypeId", mEventTypeId,
        "isActive", mIsActive
    );
}

unsigned char *MRule::get_name()
{
  return mName;
}

unsigned char *MRule::get_function()
{
  return mFunction;
}

unsigned char *MRule::get_context(bool copy)
{
    if(copy) {
        unsigned char *ret = new unsigned char[strlen((const char *)mContext) + 1];
        memcpy(ret, mContext, strlen((const char *)mContext) + 1);
        return ret;
    }
    return mFunction;
}

int MRule::get_event_type_id()
{
    return mEventTypeId;
}

int MRule::get_is_active()
{
  return mIsActive;
}


int MRule::set_name(unsigned char *name, bool copy)
{
  return set_text_field(name, &mName, copy);
}

int MRule::set_function(unsigned char *function, bool copy)
{
  return set_text_field(function, &mFunction, copy);
}

int MRule::set_context(unsigned char *context, bool copy)
{
  return set_text_field(context, &mContext, copy);
}

int MRule::set_event_type_id(int eventTypeId)
{
    mEventTypeId = eventTypeId;
    return 1;
}

int MRule::set_is_active(int isActive)
{
  mIsActive = isActive;
  return 1;
}
