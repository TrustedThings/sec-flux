#include "event.h"
#include "event_type.h"

MEvent::MEvent(sqlite3 **db): MObject(db)
{
  mTable = "events";
  
  mClientId = -1;
  mEventTypeId = -1;
  mProperties = NULL;
  mTimestamp = NULL;
}


MEvent::~MEvent()
{
  if(mProperties != NULL) delete[] mProperties;
  if(mTimestamp != NULL) delete[] mTimestamp;
}

json_t *MEvent::get_events(sqlite3 **db, map<string, string>& params)
{
    int res;
    json_t *json = json_array();
    int eventTypeId = 0;
    vector<string> filters;
    size_t pos;
    int i;
    string s;

    add_int_filter(params, filters, "clientId", "client_id");
    add_int_filter(params, filters, "eventTypeId", "event_type_id");

    string filter = generate_filter(filters);

    string request = string("SELECT id, client_id, event_type_id, properties, timestamp FROM events") + filter;
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request.c_str(), -1, &statement, NULL);
    res = sqlite3_step(statement);

    while(res == SQLITE_ROW){
        json_t *event = json_pack("{s:i,s:i,s:i,s:s}",
            "id", sqlite3_column_int(statement, 0),
            "clientId", sqlite3_column_int(statement, 1),
            "eventTypeId", sqlite3_column_int(statement, 2),
            "timestamp", sqlite3_column_text(statement, 4)
        );
        json_parse_and_set_new(event, "properties", sqlite3_column_text(statement, 3));
        json_array_append_new(json, event);
        res = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    return json;
}

int MEvent::save()
{
  int res;
  if(mProperties == NULL || mTimestamp == NULL || mClientId < 0 || mEventTypeId < 0){
    return err("missing fields", error_misc);
  }
  const char *request = mNew 
    ? "INSERT INTO events (client_id, event_type_id, properties, timestamp) VALUES (?, ?, ?, ?);"
    : "UPDATE events SET client_id = ?, event_type_id = ?, properties = ?, timestamp = ? WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mClientId);
  sqlite3_bind_int(statement, 2, mEventTypeId);
  sqlite3_bind_text(statement, 3, (const char *)mProperties, -1, SQLITE_STATIC);
  sqlite3_bind_text(statement, 4, (const char *)mTimestamp, -1, SQLITE_STATIC);
  if(!mNew) sqlite3_bind_int(statement, 5, mId);
  res = sqlite3_step(statement);
  sqlite3_finalize(statement);
  if(res != SQLITE_DONE) {
    return err("error saving event", error_misc);
  }
  if(mNew) mId = sqlite3_last_insert_rowid(mDb);
  mNew = false;
  return 1;
}

int MEvent::get_by_id()
{
  if(mNew){
    return err("missing id", error_misc);
  }
  int res;
  const char *request = "SELECT client_id, event_type_id, properties, timestamp FROM events WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mId);
  res = sqlite3_step(statement);
  if(res != SQLITE_ROW) {
    err("no event found", error_misc);
    sqlite3_finalize(statement);
    return 0;
  }
  mClientId = sqlite3_column_int(statement, 0);
  mEventTypeId = sqlite3_column_int(statement, 1);
  set_text_field(statement, 2, &mProperties);
  set_text_field(statement, 3, &mTimestamp);

  sqlite3_finalize(statement);
  return 1;
}

int MEvent::validate()
{
  // client id
  if(mClientId < 0) return err("missing client id", error_misc);
  MClient client(&mDb);
  if(client.check_exists(mClientId) != 1) return err("client not found", error_misc);
  // event type id
  if(mEventTypeId < 0) return err("missing event type id", error_misc);
  MEventType eventType(&mDb);
  if(eventType.check_exists(mEventTypeId) != 1) return err("event type not found", error_misc);
  // properties
  if(mProperties == NULL || strlen((const char *)mProperties) == 0){
    return err("properties empty", error_misc);
  }
  // timestamp
  if(mTimestamp == NULL || strlen((const char *)mTimestamp) == 0){
    return err("schema empty", error_misc);
  }
  return 1;
}

int MEvent::create_from_json_string(const char *str)
{
  int ret;
  json_auto_t *json;
  json_t *jsonProperties;
  json_error_t jsonError;
  const char *timestamp;
  // Extract json
  json = json_loads(str, 0, &jsonError);
  if(json == NULL) return err("no valid json", error_misc);
  ret = json_unpack_ex(json, &jsonError, JSON_STRICT, "{s:i,s:i,s:o,s:s}", 
  "clientId", &mClientId, 
  "eventTypeId", &mEventTypeId,
  "properties", &jsonProperties,
  "timestamp", &timestamp);
  if(ret != 0) return err("malformed json", error_misc);
  set_timestamp((unsigned char *)timestamp, true);
  set_properties(json_to_unsigned_char(jsonProperties, 0), false);
  if(validate() != 1) return 0;
  if(save() != 1){
    printf("error saving event!");
    return 0;
  }
  return 1;
}

json_t *MEvent::to_json()
{
  json_error_t error;
  json_t *jsonProperties = json_loads((const char *)mProperties, 0, &error);
  return json_pack("{s:i,s:i,s:i,s:o,s:s}", 
    "id", mId,
    "clientId", mClientId, 
    "eventTypeId", mEventTypeId,
    "properties", jsonProperties,
    "timestamp", mTimestamp);
}

int MEvent::get_client_id()
{
    return mClientId;
}

int MEvent::get_event_type_id()
{
    return mEventTypeId;
}

unsigned char *MEvent::get_properties()
{
  return mProperties;
}

unsigned char *MEvent::get_timestamp()
{
  return mTimestamp;
}

int MEvent::set_client_id(int clientId)
{
  mClientId = clientId;
  return 1;
}

int MEvent::set_event_type_id(int eventTypeId)
{
  mEventTypeId = eventTypeId;
  return 1;
}

int MEvent::set_properties(unsigned char *properties, bool copy)
{
  return set_text_field(properties, &mProperties, copy);
}

int MEvent::set_timestamp(unsigned char *timestamp, bool copy)
{
  return set_text_field(timestamp, &mTimestamp, copy);
}