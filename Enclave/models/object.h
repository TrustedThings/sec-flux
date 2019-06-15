#ifndef MOBJECT_H
#define MOBJECT_H

#include "../database/sqlite3.h"
#include "../crypto/crypto.h"
#include "../json.h"
#include "../error/errorable.h"
#include <string>
#include <vector>
#include <map>

using namespace std;

class MObject: public Errorable
{
  public:

    MObject(sqlite3 **db);

    sqlite3 *mDb;
    string mTable;
    int mId;
    bool mNew;

    int set_text_field(sqlite3_stmt *statement, int col, unsigned char **field);
    int set_text_field(unsigned char *from, unsigned char **to, bool copy);
    int check_exists(int id);
    int get_id();
    int delete_by_id();
    int set_id(int id);

    static int add_int_filter(map<string, string>& params, vector<string>& filters, string queryKey, string sqlKey);
    static string generate_filter(vector<string>& filters);
};

#endif
