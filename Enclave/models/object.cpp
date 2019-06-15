#include "object.h"

MObject::MObject(sqlite3 **db)
{
    mDb = *db;
    mNew = true;
}

int MObject::delete_by_id()
{
  if(mNew) return err("missing id", error_misc);
  int res;
  std::string request = "DELETE FROM " + mTable + " WHERE id = ?;";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request.c_str(), -1, &statement, NULL);
  sqlite3_bind_int(statement, 1, mId);
  res = sqlite3_step(statement);
  sqlite3_finalize(statement);
  if(res != SQLITE_DONE) return err("unable to delete entity", error_misc);
  return 1;
}

int MObject::set_text_field(sqlite3_stmt *statement, int col, unsigned char **field)
{
    int len = sqlite3_column_bytes(statement, col);
    if(*field != NULL) delete[] *field;
    *field = new unsigned char[len + 1];
    const unsigned char *tmp = sqlite3_column_text(statement, col);
    memcpy(*field, tmp, len);
    (*field)[len] = '\0';
    return 1;
}

int MObject::set_text_field(unsigned char *from, unsigned char **to, bool copy)
{
    int len = strlen((const char *)from);
    if(*to != NULL) delete[] *to;
    if(copy) {
        *to = new unsigned char[len + 1];
        memcpy(*to, from, len + 1);
    } else {
        *to = from;
    }
    return 1;
}

int MObject::check_exists(int id)
{
    int res;
    std::string request = "SELECT 1 FROM " + mTable + " WHERE id = ? LIMIT 1;";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(mDb, request.c_str(), -1, &statement, NULL);
    sqlite3_bind_int(statement, 1, id);
    res = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return res == SQLITE_ROW;
}

int MObject::get_id()
{
    return mId;
}

int MObject::set_id(int id)
{
    mId = id;
    mNew = false;
    return 1;
}

int MObject::add_int_filter(map<string, string> &params, vector<string>& filters, string queryKey, string sqlKey)
{
    size_t pos;
    int i;
    string s;
    if(params.count(queryKey) == 1) {
        s = params[queryKey];
        if(isdigit(s.at(0))) {
            i = stoi(s, &pos);
            if(pos == s.length()) {
                filters.push_back(string(sqlKey) + " = " + s);
                return 1;
            }
        }
    }
    return 0;
}

string MObject::generate_filter(vector<string>& filters)
{
    string filter = "";
    string glue = " AND ";
    if(filters.size() > 0) {
        filter = " WHERE ";
        for(vector<string>::iterator it = filters.begin(); it != filters.end(); it++) {
            filter += (*it) + glue;
        }
        filter = filter.substr(0, filter.length() - glue.length());
    }
    return filter;
}