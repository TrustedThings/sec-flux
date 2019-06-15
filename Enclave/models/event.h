#ifndef MODELS_EVENT_H
#define MODELS_EVENT_H

#include "object.h"
#include "client.h"

class MEvent: public MObject
{
  public:
    MEvent(sqlite3 **db);
    ~MEvent();

    static json_t *get_events(sqlite3 **db, map<string, string>& params);
    int save();
    int get_by_id();

    int validate();
    int create_from_json_string(const char *str);
    json_t *to_json();

    int get_client_id();
    int get_event_type_id();
    unsigned char *get_properties();
    unsigned char *get_timestamp();

    int set_client_id(int clientId);
    int set_event_type_id(int eventTypeId);
    int set_properties(unsigned char *properties, bool copy);
    int set_timestamp(unsigned char *timestamp, bool copy);


  private:

    int mClientId;
    int mEventTypeId;
    unsigned char *mProperties;
    unsigned char *mTimestamp;


};

#endif
