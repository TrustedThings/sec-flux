#include "version.h"
#include <string>

void MVersion::get(sqlite3 **db)
{    
    int res;
    const char *request = "SELECT version FROM versions";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    res = sqlite3_step(statement);
    mVersion = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
}

json_t *MVersion::to_json()
{
    json_t *json = json_pack("{s:i}", 
        "version", mVersion
    );
    return json;
}