#ifndef DATA_MANAGER_H
#define DATA_MANAGER_H

#include "../utils.h"
#include "../error/errorable.h"
#include "sqlite3.h"
#include "../crypto/crypto.h"
#include <string>
using namespace std;

#define SQLITE_IO_N_TRIES 15

class DataManager: public Errorable
{
  public:
    DataManager();
    ~DataManager();

    int init(const char *name);

    sqlite3 **get_db_ptr();
    const char *mName;

    int increment_version();
    int seal_db();
    int archive_event(const char *dump, const char *filename);

  private:
    const char *mFileName;
    sqlite3 *mDb;
    string mDump;
    int create_table(const char *request);
    int create_tables();

    int dump_db(sqlite3 *db);
    int unseal_db(sqlite3 *db);

};

#endif
