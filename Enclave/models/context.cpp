#include "context.h"
#include <string>

char *MContext::get_context(sqlite3 **db)
{    
    int res;
    const char *request = "SELECT value FROM contexts";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    res = sqlite3_step(statement);
    int len = sqlite3_column_bytes(statement, 0);
    char *context = new char[len + 1];
    const unsigned char *tmp = sqlite3_column_text(statement, 0);
    memcpy(context, tmp, strlen((const char *)tmp) + 1);
    sqlite3_finalize(statement);
    return context;
}

int MContext::set_context(sqlite3 **db, const char *context)
{
    int res;
    const char *request = "UPDATE contexts SET value = ?";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    sqlite3_bind_text(statement, 1, context, -1, SQLITE_STATIC);
    res = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return 1;
}
