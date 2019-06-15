#ifndef MODELS_CLIENT_H
#define MODELS_CLIENT_H

#include "object.h"

class MClient: public MObject
{
  public:
    MClient(sqlite3 **db);
    ~MClient();

    static json_t *get_clients(sqlite3 **db, int from, const char *orderBy);
    int save();
    int get_by_id();
    int get_by_pub_hex_kex();

    int validate();
    int create_from_json_string(const char *str);
    int update_from_json_string(const char *str);
    json_t *to_json();
    const char *to_string();

    unsigned char *get_name();
    bool get_is_active();
    bool get_is_admin();
    unsigned char *get_pub_key_x_hex();
    unsigned char *get_pub_key_y_hex();

    int set_name(unsigned char *name, bool copy);
    int set_pub_key_x_hex(unsigned char *pubKeyXHex, bool copy);
    int set_pub_key_y_hex(unsigned char *pubKeyYHex, bool copy);
    int set_is_admin(int isAdmin);
    int set_is_active(int isActive);


  private:

    unsigned char *mName;
    int mIsAdmin;
    int mIsActive;
    unsigned char *mPubKeyXHex;
    unsigned char *mPubKeyYHex;

};

#endif
