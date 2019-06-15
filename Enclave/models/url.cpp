#include "url.h"

MUrl::MUrl(sqlite3 **db): MObject(db)
{
  mValue = NULL;
}


MUrl::~MUrl()
{
  if(mValue != NULL) delete[] mValue;
}

int MUrl::save()
{
  int res;
  if(mValue == NULL){
    return err("missing fields", error_misc);
  }
  const char *request = mNew 
    ? "INSERT INTO urls (value) VALUES (?);"
    : "UPDATE urls SET value = ? WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_text(statement, 1, (const char *)mValue, -1, SQLITE_STATIC);
  if(!mNew) sqlite3_bind_int(statement, 2, mId);
  res = sqlite3_step(statement);
  sqlite3_finalize(statement);
  if(res != SQLITE_DONE) {
    return err("error saving url", error_misc);
  }
  if(mNew) mId = sqlite3_last_insert_rowid(mDb);
  mNew = false;
  return 1;
}

int MUrl::get_by_id()
{
  if(mNew){
    return err("missing id", error_misc);
  }
  int res;
  const char *request = "SELECT value FROM urls WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mId);
  res = sqlite3_step(statement);
  if(res != SQLITE_ROW) {
    err("no url found", error_misc);
    sqlite3_finalize(statement);
    return 0;
  }
  set_text_field(statement, 0, &mValue);

  sqlite3_finalize(statement);
  return 1;
}

int MUrl::validate()
{
  // value
  if(mValue == NULL || strlen((const char *)mValue) == 0){
    return err("value empty", error_misc);
  }
  return 1;
}

int MUrl::create_from_json_string(const char *str)
{
  int ret;
  json_auto_t *json;
  json_error_t jsonError;
  const char *value;
  // Extract json
  json = json_loads(str, 0, &jsonError);
  if(json == NULL) return err("no valid json", error_misc);
  ret = json_unpack_ex(json, &jsonError, JSON_STRICT, 
  "{s:s}", "value", &value);
  if(ret != 0) return err("malformed json", error_misc);
  set_value((unsigned char *)value, true);
  if(validate() != 1) return 0;
  if(save() != 1){
    printf("error saving url!");
    return 0;
  }
  return 1;
}

int MUrl::update_from_json_string(const char *str)
{
  if(mNew || get_by_id() != 1) return err("no url", error_misc);
  int ret;
  json_auto_t *json;
  json_error_t jsonError;
  const char *value;
  // Extract json
  json = json_loads(str, 0, &jsonError);
  ret = json_unpack_ex(json, &jsonError, JSON_STRICT, 
  "{s:s}", "value", &value);
  if(ret != 0) return err("malformed json", error_misc);
  set_value((unsigned char *)value, true);
  if(validate() != 1) return 0;
    if(save() != 1){
    printf("error saving url!");
    return 0;
  }
  return 1;
}

json_t *MUrl::to_json()
{
  return json_pack("{s:s}", 
    "value", mValue);
}


unsigned char *MUrl::get_value()
{
  return mValue;
}

int MUrl::set_value(unsigned char *value, bool copy)
{
  return set_text_field(value, &mValue, copy);
}
