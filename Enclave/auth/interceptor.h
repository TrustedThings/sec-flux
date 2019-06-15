#ifndef INTERCEPTOR_H
#define INTERCEPTOR_H

#include "../database/sqlite3.h"
#include "../error/errorable.h"
#include <map>
#include <string>
#include "../request/request.h"
#include "session.h"


using namespace std;


class Interceptor: public Errorable
{
    public:
        Interceptor();
        ~Interceptor();

        int init(sqlite3 **db);

        int decrypt_request(Request *request);
        int encrypt_response(Request *request);
        
    private:
    
        sqlite3 **mDb;

};

#endif