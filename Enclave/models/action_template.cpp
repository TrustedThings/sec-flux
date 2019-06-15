#include "action_template.h"
#include "models.h"

MActionTemplate::MActionTemplate(sqlite3 **db): MObject(db)
{
  mTable = "action_templates";
  
  mName = NULL;
  mRuleId = -1;
  mActionTypeId = -1;
  mFunction = NULL;
  mContext = NULL;
}


MActionTemplate::~MActionTemplate()
{
  if(mName != NULL) delete[] mName;
  if(mFunction != NULL) delete[] mFunction;
  if(mContext != NULL) delete[] mContext;
}

json_t *MActionTemplate::get(sqlite3 **db, int from, const char *orderBy)
{
    int res;
    json_t *json = json_array();

    const char *request = "SELECT id, name, rule_id, action_type_id, function, context FROM action_templates;";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    res = sqlite3_step(statement);

    while(res == SQLITE_ROW){
        json_t *actionTemplate = json_pack("{s:i,s:s,s:i,s:i,s:s,s:s}",
            "id", sqlite3_column_int(statement, 0),
            "name", sqlite3_column_text(statement, 1),
            "ruleId", sqlite3_column_int(statement, 2),
            "actionTypeId", sqlite3_column_int(statement, 3),
            "function", sqlite3_column_text(statement, 4),
            "context", sqlite3_column_text(statement, 5)
        );
        json_array_append_new(json, actionTemplate);
        res = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    return json;
}

vector<MActionTemplate*> MActionTemplate::get_by_rule_id(sqlite3 **db, int ruleId)
{
    int ret;
    vector<MActionTemplate*> actionTemplates;
    MActionTemplate *actionTemplate;
    const char *request = "SELECT id, name, rule_id, action_type_id, function, context FROM action_templates WHERE rule_id = ?;";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    sqlite3_bind_int(statement, 1, ruleId);
    ret = sqlite3_step(statement);

    while(ret == SQLITE_ROW) {
        actionTemplate = new MActionTemplate(db);
        unsigned char *function = NULL;
        unsigned char *context = NULL;
        unsigned char *name = NULL;
        actionTemplate->set_id(sqlite3_column_int(statement, 0));
        actionTemplate->set_text_field(statement, 1, &name);
        actionTemplate->set_name(name, false);
        actionTemplate->set_rule_id(sqlite3_column_int(statement, 2));
        actionTemplate->set_action_type_id(sqlite3_column_int(statement, 3));
        actionTemplate->set_text_field(statement, 4, &function);
        actionTemplate->set_function(function, false);
        actionTemplate->set_text_field(statement, 5, &context);
        actionTemplate->set_context(context, false);
        actionTemplates.push_back(actionTemplate);
        ret = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);

    return actionTemplates;
}

int MActionTemplate::save()
{
  int res;
  if(!validate()){
    return err("missing fields", error_misc);
  }
  const char *request = mNew 
    ? "INSERT INTO action_templates (name, rule_id, action_type_id, function, context) VALUES (?, ?, ?, ?, ?);"
    : "UPDATE action_templates SET name = ?, rule_id = ?, action_type_id = ?, function = ?, context = ? WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_text(statement, 1, (const char *)mName, -1, SQLITE_STATIC);
  sqlite3_bind_int(statement, 2, mRuleId);
  sqlite3_bind_int(statement, 3, mActionTypeId);
  sqlite3_bind_text(statement, 4, (const char *)mFunction, -1, SQLITE_STATIC);
  sqlite3_bind_text(statement, 5, (const char *)mContext, -1, SQLITE_STATIC);
  if(!mNew) sqlite3_bind_int(statement, 6, mId);
  res = sqlite3_step(statement);
  sqlite3_finalize(statement);
  if(res != SQLITE_DONE) {
    return err("error saving action template", error_misc);
  }
  if(mNew) mId = sqlite3_last_insert_rowid(mDb);
  mNew = false;
  return 1;
}

int MActionTemplate::get_by_id()
{
  if(mNew){
    return err("missing id", error_misc);
  }
  int res;
  const char *request = "SELECT name, rule_id, action_type_id, function, context FROM action_templates WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mId);
  res = sqlite3_step(statement);
  if(res != SQLITE_ROW) {
    err("no action template found", error_misc);
    sqlite3_finalize(statement);
    return 0;
  }
  set_text_field(statement, 0, &mName);
  mRuleId = sqlite3_column_int(statement, 1);
  mActionTypeId = sqlite3_column_int(statement, 2);
  set_text_field(statement, 3, &mFunction);
  set_text_field(statement, 4, &mContext);

  sqlite3_finalize(statement);
  return 1;
}

int MActionTemplate::validate()
{
  MRule rule(&mDb);
  MActionType actionType(&mDb);
  // Name
  if(mName == NULL || strlen((const char *)mName) == 0){
    return err("name empty", error_misc);
  }
  // Rule
  if(mRuleId == -1) return err("rule id missing", error_misc);
  if(!rule.check_exists(mRuleId)) return err("rule non existing", error_misc);
  // Action type
  if(mActionTypeId == -1) return err("action type id missing", error_misc);
  if(!actionType.check_exists(mActionTypeId)) return err("action type non existing", error_misc);
  // Function
  if(mFunction == NULL || strlen((const char *)mFunction) == 0){
    return err("function empty", error_misc);
  }
  // Context
  if(mContext == NULL || strlen((const char *)mContext) == 0){
    return err("context empty", error_misc);
  }
  return 1;
}

int MActionTemplate::create_from_json(json_t *json)
{
  int ret;
  json_error_t error;
  const char *name, *function, *context;
  ret = json_unpack_ex(json, &error, JSON_STRICT, 
    "{s:s,s:i,s:i,s:s,s:s}", 
    "name", &name, 
    "ruleId", &mRuleId,
    "actionTypeId", &mActionTypeId,
    "function", &function,
    "context", &context
  );
  if(ret != 0) return err("malformed json", error_misc);
  set_name((unsigned char *)name, true);
  set_function((unsigned char *)function, true);
  set_context((unsigned char *)context, true);
  if(validate() != 1) return 0;
  if(save() != 1){
    printf("error saving action template!");
    return 0;
  }
  return 1;
}

int MActionTemplate::update_from_json(json_t *json, bool write)
{
  if(mNew || get_by_id() != 1) return err("no action template", error_misc);
  int ret;
  json_error_t error;
  const char *name, *function, *context;
  // Extract json
  ret = json_unpack_ex(json, &error, JSON_STRICT, 
    "{s:s,s:i,s:i,s:s,s:s}", 
    "name", &name, 
    "ruleId", &mRuleId,
    "actionTypeId", &mActionTypeId,
    "function", &function,
    "context", &context
  );
  if(ret != 0) return err("malformed json", error_misc);
  set_name((unsigned char *)name, true);
  set_function((unsigned char *)function, true);
  set_context((unsigned char *)context, true);
  if(validate() != 1) return 0;
  if(!write) return 1;
  if(save() != 1){
    printf("error saving action template!");
    return 0;
  }
  return 1;
}

json_t *MActionTemplate::to_json()
{
  json_t *json = json_pack("{s:i,s:s,s:i,s:i,s:s,s:s}", 
    "id", mId,
    "name", mName,
    "ruleId", mRuleId,
    "actionTypeId", mActionTypeId,
    "function", mFunction,
    "context", mContext
  );
  return json;
}

const char *MActionTemplate::to_string()
{
    json_auto_t *json = to_json();
    const char *str = json_dumps(json, JSON_COMPACT);
    return str;
}

unsigned char *MActionTemplate::get_name()
{
  return mName;
}

int MActionTemplate::get_rule_id()
{
    return mRuleId;
}

int MActionTemplate::get_action_type_id()
{
    return mActionTypeId;
}

unsigned char *MActionTemplate::get_function()
{
  return mFunction;
}

unsigned char *MActionTemplate::get_context(bool copy)
{
  if(copy) {
    unsigned char *ret = new unsigned char[strlen((const char *)mContext) + 1];
    memcpy(ret, mContext, strlen((const char *)mContext) + 1);
    return ret;
  }
  return mContext;
}

int MActionTemplate::set_name(unsigned char *name, bool copy)
{
  return set_text_field(name, &mName, copy);
}

int MActionTemplate::set_rule_id(int ruleId)
{
    mRuleId = ruleId;
}

int MActionTemplate::set_action_type_id(int actionTypeId)
{
    mActionTypeId = actionTypeId;
}

int MActionTemplate::set_function(unsigned char *function, bool copy)
{
  return set_text_field(function, &mFunction, copy);
}

int MActionTemplate::set_context(unsigned char *context, bool copy)
{
  return set_text_field(context, &mContext, copy);
}