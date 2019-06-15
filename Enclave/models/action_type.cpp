#include "action_type.h"

MActionType::MActionType(sqlite3 **db): MObject(db)
{
  mTable = "action_types";
  
  mName = NULL;
  mSchema = NULL;
}


MActionType::~MActionType()
{
  if(mName != NULL) delete[] mName;
  if(mSchema != NULL) delete[] mSchema;
}

json_t *MActionType::get_action_types(sqlite3 **db, int from, const char *orderBy)
{
    int res;
    json_t *json = json_array();
    const char *request = "SELECT id, name, schema FROM action_types;";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    res = sqlite3_step(statement);

    while(res == SQLITE_ROW){
        json_t *actionType = json_pack("{s:i,s:s}",
            "id", sqlite3_column_int(statement, 0),
            "name", sqlite3_column_text(statement, 1)
        );
        json_parse_and_set_new(actionType, "schema", sqlite3_column_text(statement, 2));
        json_array_append_new(json, actionType);
        res = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    return json;
}

int MActionType::save()
{
  int res;
  if(mName == NULL || mSchema == NULL){
    return err("missing fields", error_misc);
  }
  const char *request = mNew 
    ? "INSERT INTO action_types (name, schema) VALUES (?, ?);"
    : "UPDATE action_types SET name = ?, schema = ? WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_text(statement, 1, (const char *)mName, -1, SQLITE_STATIC);
  sqlite3_bind_text(statement, 2, (const char *)mSchema, -1, SQLITE_STATIC);
  if(!mNew) sqlite3_bind_int(statement, 3, mId);
  res = sqlite3_step(statement);
  sqlite3_finalize(statement);
  if(res != SQLITE_DONE) {
    return err("error saving action type", error_misc);
  }
  if(mNew) mId = sqlite3_last_insert_rowid(mDb);
  mNew = false;
  return 1;
}

int MActionType::get_by_id()
{
  if(mNew){
    return err("missing id", error_misc);
  }
  int res;
  const char *request = "SELECT name, schema FROM action_types WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mId);
  res = sqlite3_step(statement);
  if(res != SQLITE_ROW) {
    err("no action type found", error_misc);
    sqlite3_finalize(statement);
    return 0;
  }
  set_text_field(statement, 0, &mName);
  set_text_field(statement, 1, &mSchema);

  sqlite3_finalize(statement);
  return 1;
}

int MActionType::validate()
{
  // Name
  if(mName == NULL || strlen((const char *)mName) == 0){
    return err("name empty", error_misc);
  }
  // schema
  if(mSchema == NULL || strlen((const char *)mSchema) == 0){
    return err("schema empty", error_misc);
  }
  return 1;
}

int MActionType::create_from_json_string(const char *str)
{
  int ret;
  json_auto_t *json;
  json_t *jsonSchema;
  json_error_t jsonError;
  const char *name, *schema;
  // Extract json
  json = json_loads(str, 0, &jsonError);
  if(json == NULL) return err("no valid json", error_misc);
  ret = json_unpack_ex(json, &jsonError, JSON_STRICT, 
  "{s:s,s:o}", "name", &name, "schema", &jsonSchema);
  if(ret != 0) return err("malformed json", error_misc);
  set_name((unsigned char *)name, true);
  set_schema(json_to_unsigned_char(jsonSchema, 0), false);
  if(validate() != 1) return 0;
  if(save() != 1){
    printf("error saving action type!");
    return 0;
  }
  return 1;
}

int MActionType::update_from_json_string(const char *str)
{
  if(mNew || get_by_id() != 1) return err("no action type", error_misc);
  int ret;
  json_auto_t *json;
  json_t *jsonSchema;
  json_error_t jsonError;
  const char *name;
  // Extract json
  json = json_loads(str, 0, &jsonError);
  ret = json_unpack_ex(json, &jsonError, JSON_STRICT, 
  "{s?:s,s?:o}", "name", &name, "schema", &jsonSchema);
  if(ret != 0) return err("malformed json", error_misc);
  if(name != NULL) set_name((unsigned char *)name, true);
  if(jsonSchema != NULL) set_schema(json_to_unsigned_char(jsonSchema, 0), false);
  if(validate() != 1) return 0;
    if(save() != 1){
    printf("error saving action type!");
    return 0;
  }
  return 1;
}

json_t *MActionType::to_json()
{
  json_error_t error;
  json_t *jsonSchema = json_loads((const char *)mSchema, 0, &error);
  return json_pack("{s:i,s:s,s:o}", 
    "id", mId, "name", mName, "schema", jsonSchema);
}

const char *MActionType::to_string()
{
    json_auto_t *json = to_json();
    const char *str = json_dumps(json, JSON_COMPACT);
    return str;
}

unsigned char *MActionType::get_name()
{
  return mName;
}

unsigned char *MActionType::get_schema()
{
  return mSchema;
}

int MActionType::set_name(unsigned char *name, bool copy)
{
  return set_text_field(name, &mName, copy);
}

int MActionType::set_schema(unsigned char *schema, bool copy)
{
  return set_text_field(schema, &mSchema, copy);
}