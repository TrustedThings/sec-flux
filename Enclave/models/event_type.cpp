#include "event_type.h"

MEventType::MEventType(sqlite3 **db): MObject(db)
{
  mTable = "event_types";
  
  mName = NULL;
  mSchema = NULL;
}


MEventType::~MEventType()
{
  if(mName != NULL) delete[] mName;
  if(mSchema != NULL) delete[] mSchema;
}

json_t *MEventType::get(sqlite3 **db, int from, const char *orderBy)
{
    int res;
    json_t *json = json_array();

    const char *request = "SELECT id, name, schema FROM event_types;";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    res = sqlite3_step(statement);

    while(res == SQLITE_ROW){
        json_t *eventType = json_pack("{s:i,s:s}",
            "id", sqlite3_column_int(statement, 0),
            "name", sqlite3_column_text(statement, 1)
        );
        json_parse_and_set_new(eventType, "schema", sqlite3_column_text(statement, 2));
        json_array_append_new(json, eventType);
        res = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    return json;
}

int MEventType::save()
{
  int res;
  if(mName == NULL || mSchema == NULL){
    return err("missing fields", error_misc);
  }
  const char *request = mNew 
    ? "INSERT INTO event_types (name, schema) VALUES (?, ?);"
    : "UPDATE event_types SET name = ?, schema = ? WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_text(statement, 1, (const char *)mName, -1, SQLITE_STATIC);
  sqlite3_bind_text(statement, 2, (const char *)mSchema, -1, SQLITE_STATIC);
  if(!mNew) sqlite3_bind_int(statement, 3, mId);
  res = sqlite3_step(statement);
  sqlite3_finalize(statement);
  if(res != SQLITE_DONE) {
    return err("error saving event type", error_misc);
  }
  if(mNew) mId = sqlite3_last_insert_rowid(mDb);
  mNew = false;
  return 1;
}

int MEventType::get_by_id()
{
  if(mNew){
    return err("missing id", error_misc);
  }
  int res;
  const char *request = "SELECT name, schema FROM event_types WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mId);
  res = sqlite3_step(statement);
  if(res != SQLITE_ROW) {
    err("no event type found", error_misc);
    sqlite3_finalize(statement);
    return 0;
  }
  set_text_field(statement, 0, &mName);
  set_text_field(statement, 1, &mSchema);

  sqlite3_finalize(statement);
  return 1;
}

int MEventType::validate()
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

int MEventType::create_from_json_string(const char *str)
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
    printf("error saving event type!");
    return 0;
  }
  return 1;
}

int MEventType::update_from_json_string(const char *str)
{
  if(mNew || get_by_id() != 1) return err("no event type", error_misc);
  int ret;
  json_auto_t *json;
  json_t *jsonSchema;
  json_error_t jsonError;
  const char *name;
  // Extract json
  json = json_loads(str, 0, &jsonError);
  ret = json_unpack_ex(json, &jsonError, JSON_STRICT, 
  "{s:s,s:o}", "name", &name, "schema", &jsonSchema);
  if(ret != 0) return err("malformed json", error_misc);
  set_name((unsigned char *)name, true);
  set_schema(json_to_unsigned_char(jsonSchema, 0), false);
  if(validate() != 1) return 0;
    if(save() != 1){
    printf("error saving event type!");
    return 0;
  }
  return 1;
}

json_t *MEventType::to_json()
{
  json_t *json = json_pack("{s:i,s:s}", 
    "id", mId,
    "name", mName
  );
  json_parse_and_set_new(json, "schema", mSchema);
  return json;
}

const char *MEventType::to_string()
{
    json_auto_t *json = to_json();
    const char *str = json_dumps(json, JSON_COMPACT);
    return str;
}

unsigned char *MEventType::get_name()
{
  return mName;
}

unsigned char *MEventType::get_schema()
{
  return mSchema;
}

int MEventType::set_name(unsigned char *name, bool copy)
{
  return set_text_field(name, &mName, copy);
}

int MEventType::set_schema(unsigned char *schema, bool copy)
{
  return set_text_field(schema, &mSchema, copy);
}