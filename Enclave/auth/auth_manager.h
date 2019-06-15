#ifndef AUTH_MANAGER_H
#define AUTH_MANAGER_H

#include "../database/sqlite3.h"
#include "../error/errorable.h"
#include <map>
#include <string>
#include "exchange.h"
#include "session.h"
#include <openssl/ec.h>
#include "ecdhe_m.h"
#include "interceptor.h"


using namespace std;


class AuthManager: public Errorable
{
    public:
        AuthManager();
        ~AuthManager();

        int init(sqlite3 **db);

        int step1(const char *message1, int clientId, int *message2_len);
        int step2(const char *message3, int clientId, int *message4_len);

        int check_message_1(const char *message1, int clientId);
        int create_message_2(int clientId, int *message2_len);
        int check_message_3(const char *message3, int clientId);
        int create_message_4(int clientId, int *message4_len);

        int increment_and_get_session_id(int *id);

        int get_message(char **message);

        int decrypt_session_message(Request *request);
        int authenticate(Request *request);
        int encrypt_session_response(Request *request);
        
    private:
        sqlite3 **mDb;
        map<int, exchange> mExchanges; // key: cid
        map<int, session> mSessions; // Key: cid
        map<int, int> mDirectory; // Key: kid, value: cid

        ECDHE_M *mMessage;

        Interceptor mInterceptor;

        // DEBUG
        EC_KEY *mMainKey;
        int mLastSessionId;

};

#endif