#ifndef EXCHANGE_H
#define EXCHANGE_H

#include "../crypto/crypto.h"
#include <string>
#include "ecdhe.h"

using namespace std;

typedef struct exchange {
    int clientId;
    unsigned char serverExchangeId[ECDHE_EXCHANGE_ID_LEN];
    unsigned char clientExchangeId[ECDHE_EXCHANGE_ID_LEN];
    unsigned char serverPrivateKey[KEY_LEN];
    unsigned char clientPubKeyX[KEY_LEN];
    unsigned char clientPubKeyY[KEY_LEN];
    unsigned char aad2[SHA256_DIGEST_LENGTH];
    unsigned char sharedKey[KEY_LEN];
    char message1[1000];
} exchange;

#endif