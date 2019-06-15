#ifndef SESSION_H
#define SESSION_H

#include "../crypto/crypto.h"

typedef struct session {
    // TODO: add expiry time
    unsigned char key[KEY_LEN];
    int sessionId;
    int clientId;
} session;

#endif