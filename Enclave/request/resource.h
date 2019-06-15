#ifndef RESOURCE_H
#define RESOURCE_H

#include "request.h"
#include <string>
#include <vector>
#include <map>

using namespace std;

typedef void (*Handler)(sqlite3**, Request*); 

class Resource{
    public:
        Resource();
        ~Resource();

        string get_path();
        void set_path(string path);

        int match(Request *request);

        void set_handler(string method, Handler handler);

        void handle(sqlite3 **db, Request *request);

    private:
        string mPath;
        map<string, Handler> mHandlers;

};





#endif