#ifndef REQUEST_MANAGER_H
#define REQUEST_MANAGER_H

#include "../database/sqlite3.h"
#include "request.h"
#include "resource.h"
#include <vector>

#define SQLITE_DB_NAME "trustno1.db"
#define SQLITE_ARCHIVE_DB_NAME "trustno1_archive.db"

using namespace std;

class RequestManager {
    public:
        RequestManager();
        ~RequestManager();

        int init(sqlite3 **ptr);

        void set_request(Request *request);
        int do_request(int *backup);
        Request *get_request();
        int get_response_length();

        void add_resource(Resource *resource);

        sqlite3 **get_db_ptr();

    private:

        static bool resource_compare(Resource *i, Resource *j);

        static int resource_priority(Resource *resource);

        sqlite3 **mDb;
        Request *mRequest;
        vector<Resource*> mResources;
};


#endif