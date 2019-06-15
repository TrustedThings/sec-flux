#include "client.h"
#include "../utils.h"

MClient::MClient(sqlite3 **db): MObject(db)
{
  mTable = "clients";
  
  mName = NULL;
  mPubKeyXHex = NULL;
  mPubKeyYHex = NULL;
  mIsAdmin = -1;
  mIsActive = -1;
}


MClient::~MClient()
{
  if(mName != NULL) delete[] mName;
  if(mPubKeyXHex != NULL) delete[] mPubKeyXHex;
  if(mPubKeyYHex != NULL) delete[] mPubKeyYHex;
}


json_t *MClient::get_clients(sqlite3 **db, int from, const char *orderBy)
{
  int res;
  json_t *json = json_array();

  const char *request = "SELECT id, name, pub_key_x_hex, pub_key_y_hex, is_admin, is_active FROM clients;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
  res = sqlite3_step(statement);
  //if(res != SQLITE_ROW && res != SQLITE_DONE) return err("error getting clients", error_misc);

  while(res == SQLITE_ROW){
    json_t *client = json_pack("{s:i,s:s,s:{s:s,s:s},s:b,s:b}",
      "id", sqlite3_column_int(statement, 0),
      "name", sqlite3_column_text(statement, 1),
      "pubKey", 
      "x", sqlite3_column_text(statement, 2),
      "y", sqlite3_column_text(statement, 3),
      "isAdmin", sqlite3_column_int(statement, 4),
      "isActive", sqlite3_column_int(statement, 5)
    );
    json_array_append_new(json, client);

    res = sqlite3_step(statement);
  }
  sqlite3_finalize(statement);
  return json;
}

int MClient::save()
{
  int res;
  if(mName == NULL || mPubKeyXHex == NULL || mPubKeyYHex == NULL || mIsAdmin < 0 || mIsActive < 0){
    return err("missing fields", error_misc);
  }
  const char *request = mNew 
    ? "INSERT INTO clients (name, pub_key_x_hex, pub_key_y_hex, is_admin, is_active) VALUES (?, ?, ?, ?, ?);" 
    : "UPDATE clients SET name = ?, pub_key_x_hex = ?, pub_key_y_hex = ?, is_admin = ?, is_active = ? WHERE id = ?;";

  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_text(statement, 1, (const char *)mName, -1, SQLITE_STATIC);
  sqlite3_bind_text(statement, 2, (const char *)mPubKeyXHex, -1, SQLITE_STATIC);
  sqlite3_bind_text(statement, 3, (const char *)mPubKeyYHex, -1, SQLITE_STATIC);
  sqlite3_bind_int(statement, 4, mIsAdmin);
  sqlite3_bind_int(statement, 5, mIsActive);
  if(!mNew) sqlite3_bind_int(statement, 6, mId);
  res = sqlite3_step(statement);
  sqlite3_finalize(statement);
  if(res != SQLITE_DONE) {
    return err("error saving client", error_misc);
  }
  if(mNew) mId = sqlite3_last_insert_rowid(mDb);
  mNew = false;
  return 1;
}

int MClient::get_by_id()
{
  if(mNew){
    return err("missing id", error_misc);
  }
  int res;
  const char *request = "SELECT name, is_admin, is_active, pub_key_x_hex, pub_key_y_hex FROM clients WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mId);
  res = sqlite3_step(statement);
  if(res != SQLITE_ROW) {
    err("no client found", error_misc);
    sqlite3_finalize(statement);
    return 0;
  }
  set_text_field(statement, 0, &mName);
  mIsAdmin = sqlite3_column_int(statement, 1);
  mIsActive = sqlite3_column_int(statement, 2);
  set_text_field(statement, 3, &mPubKeyXHex);
  set_text_field(statement, 4, &mPubKeyYHex);

  sqlite3_finalize(statement);
  return 1;
}

int MClient::get_by_pub_hex_kex()
{
  if(mPubKeyXHex == NULL || mPubKeyYHex == NULL){
    return err("missing pub kex", error_misc);
  }
  int res;
  const char *request = "SELECT id, name, is_admin, is_active FROM clients WHERE pub_key_x_hex LIKE ? AND pub_key_y_hex LIKE ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_text(statement, 1, (const char *)mPubKeyXHex, -1, SQLITE_STATIC);
  sqlite3_bind_text(statement, 2, (const char *)mPubKeyYHex, -1, SQLITE_STATIC);
  res = sqlite3_step(statement);
  if(res != SQLITE_ROW) {
    err("no client found", error_misc);
    sqlite3_finalize(statement);
    return 0;
  }
  mId = sqlite3_column_int(statement, 0);
  mNew = false;
  set_text_field(statement, 1, &mName);
  mIsAdmin = sqlite3_column_int(statement, 2);
  mIsActive = sqlite3_column_int(statement, 3);

  sqlite3_finalize(statement);
  return 1;
}

int MClient::validate()
{
  // Name
  if(mName == NULL || strlen((const char *)mName) == 0){
    return err("name empty", error_misc);
  }
  // Pub key
  if(mPubKeyXHex == NULL || BN_hex2bn(NULL, (const char *)mPubKeyXHex) != PUB_KEY_COORD_LEN * 2
    || mPubKeyYHex == NULL || BN_hex2bn(NULL, (const char *)mPubKeyYHex) != PUB_KEY_COORD_LEN * 2){
    return err("missing or malformed public key coordinates", error_misc);
  }
  // Is admin
  if(mIsAdmin < 0) return err("admin rights not set", error_misc);
  // Is active
  if(mIsActive < 0) return err("active state not set", error_misc);

  return 1;
}

int MClient::create_from_json_string(const char *str)
{
  int ret;
  json_auto_t *json;
  json_error_t jsonError;
  const char *name, *crv, *kty, *x, *y;
  bool ext;
  // Extract json
  json = json_loads(str, 0, &jsonError);
  if(json == NULL) return err("no valid json", error_misc);
  ret = json_unpack_ex(json, &jsonError, JSON_STRICT, 
    "{s:{s:s,s:b,s:[*],s:s,s:s,s:s},s:b,s:b,s:s}", 
    "pubKey", 
        "crv", &crv,
        "ext", &ext,
        "key_ops", 
        "kty", &kty,
        "x", &x, 
        "y", &y, 
    "isAdmin", &mIsAdmin, 
    "isActive", &mIsActive,
    "name", &name
  );
  if(ret != 0) return err("malformed json", error_misc);
  set_name((unsigned char *)name, true);
  set_pub_key_x_hex((unsigned char *)x, true);
  set_pub_key_y_hex((unsigned char *)y, true);
  if(validate() != 1) return 0;
  if(save() != 1){
    printf("error saving client!");
    return 0;
  }
  return 1;
}

int MClient::update_from_json_string(const char *str)
{
  if(mNew || get_by_id() != 1) return err("no client", error_misc);
  int ret;
  json_auto_t *json;
  json_error_t jsonError;
  const char *name, *crv, *kty, *x, *y;
  bool ext;
  int isAdmin, isActive;
  // Extract json
  json = json_loads(str, 0, &jsonError);
  ret = json_unpack_ex(json, &jsonError, JSON_STRICT, 
    "{s:{s:s,s:b,s:[*],s:s,s:s,s:s},s:b,s:b,s:s}", 
    "pubKey", 
        "crv", &crv,
        "ext", &ext,
        "key_ops", 
        "kty", &kty,
        "x", &x, 
        "y", &y, 
    "isAdmin", &mIsAdmin, 
    "isActive", &mIsActive,
    "name", &name
  );
  if(ret != 0) return err("malformed json", error_misc);
  set_name((unsigned char *)name, true);
  set_pub_key_x_hex((unsigned char *)x, true);
  set_pub_key_y_hex((unsigned char *)y, true);
  if(validate() != 1) return 0;
    if(save() != 1){
    printf("error saving client!");
    return 0;
  }
  return 1;
}

json_t *MClient::to_json()
{
  json_t *json = json_pack(
    "{s:i,s:s,s:{s:s,s:b,s:[s],s:s,s:s,s:s},s:b,s:b}", 
    "id", mId,
    "name", mName,
    "pubKey", 
        "crv", "P-256",
        "ext", true,
        "key_ops", "verify",
        "kty", "EC",
        "x", mPubKeyXHex, 
        "y", mPubKeyYHex,
    "isActive", mIsActive,
    "isAdmin", mIsAdmin);
    return json;
}

const char *MClient::to_string()
{
    json_auto_t *json = to_json();
    const char *str = json_dumps(json, JSON_COMPACT);
    return str;
}

unsigned char *MClient::get_name()
{
  return mName;
}

bool MClient::get_is_admin()
{
  return mIsAdmin;
}

bool MClient::get_is_active()
{
  return mIsActive;
}

unsigned char *MClient::get_pub_key_x_hex()
{
  return mPubKeyXHex;
}

unsigned char *MClient::get_pub_key_y_hex()
{
  return mPubKeyYHex;
}

int MClient::set_name(unsigned char *name, bool copy)
{
  return set_text_field(name, &mName, copy);
}

int MClient::set_pub_key_x_hex(unsigned char *pubKeyXHex, bool copy)
{
  to_upper(pubKeyXHex);
  set_text_field(pubKeyXHex, &mPubKeyXHex, copy);
  return 1;
}

int MClient::set_pub_key_y_hex(unsigned char *pubKeyYHex, bool copy)
{
  to_upper(pubKeyYHex);
  set_text_field(pubKeyYHex, &mPubKeyYHex, copy);
  return 1;
}

int MClient::set_is_admin(int isAdmin)
{
  mIsAdmin = isAdmin;
  return 1;
}

int MClient::set_is_active(int isActive)
{
  mIsActive = isActive;
  return 1;
}
