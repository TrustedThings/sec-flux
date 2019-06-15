#include <string.h>

#include <memory>
#include <cstdlib>
#include <jansson.h>
#include <stdio.h>
#include <string>

#include "utils.h"
#include "error/error.h"
#include "json.h"
#include "crypto/b64url.h"

using namespace std;

int json_add_string(json_t *json, const char *key, const char *value)
{
  json_t *json_value = json_string(value);
  json_object_set_new(json, key, json_value);
  return 1;
}

int json_add_bin2b64url_string(json_t *json, const char *key, unsigned char *value, int valueLen)
{
  char *b64url = b64url_encode(value, valueLen);
  if(b64url == NULL) return 0;
  json_t *string = json_string((const char *)b64url);
  delete[] b64url;
  return json_object_set_new(json, key, string);
}

void json_print(json_t *json)
{
  size_t size = json_dumpb(json, NULL, 0, JSON_COMPACT + JSON_ENCODE_ANY);
  if(size == 0){
    printf("No JSON!\n");
    return;
  }
  char *buf = new char[size + 1];
  size = json_dumpb(json, buf, size, JSON_COMPACT + JSON_ENCODE_ANY);
  buf[size] = '\0';
  printf("JSON string: %s\n", buf);
  return;
}

void json_test(json_t *json, const char *message)
{
  size_t size = json_dumpb(json, NULL, 0, 0);
  if(size == 0){
    printf("no json: %s\n", message);
  }
  return;
}

unsigned char *json_to_unsigned_char(json_t *json, int flags)
{
  size_t size;
  size = json_dumpb(json, NULL, 0, flags);
  char *tmp = new char[size];
  size = json_dumpb(json, tmp, size, flags);
  unsigned char *data = new unsigned char[size + 1];
  memcpy(data, tmp, size);
  delete[] tmp;
  data[size] = '\0';
  return data;
}

unsigned char *json_to_unsigned_char(json_t *json, int *len, int flags)
{
  size_t size;
  size = json_dumpb(json, NULL, 0, flags);
  char *tmp = new char[size];
  size = json_dumpb(json, tmp, size, flags);
  unsigned char *data = new unsigned char[size];
  memcpy(data, tmp, size);
  *len = static_cast<int>(size);
  delete[] tmp;
  return data;
}

int json_parse_and_set_new(json_t *json, const char *key, const char *value)
{
    json_error_t error;
    json_t *jsonValue = json_loads(value, 0, &error);
    if(jsonValue == NULL) return 0;
    json_object_set_new(json, key, jsonValue);
    return 1;
}

int json_parse_and_set_new(json_t *json, const char *key, const unsigned char *value)
{
    return json_parse_and_set_new(json, key, (const char *)value);
}

json_t *jwt2jwe(char *jwtIn)
{
    string jwt = jwtIn;
    string del = ".";
    int pKey = jwt.find(del, 0);
    int pIv = jwt.find(del, pKey + 1);
    int pCiphertext = jwt.find(del, pIv + 1);
    int pTag = jwt.find(del, pCiphertext + 1);

    if(pCiphertext == -1) return NULL;

    char *headers = (char *)b64url_decode(jwt.substr(0, pKey - 0).c_str(), pKey - 0);

    string j = "{\"unprotected\":";
    j.append(headers);
    j.append(",\"iv\":\"");
    j.append(jwt.substr(pIv + 1, pCiphertext - pIv - 1));
    j.append("\",\"ciphertext\":\"");
    j.append(jwt.substr(pCiphertext + 1, pTag - pCiphertext - 1));
    j.append("\",\"tag\":\"");
    j.append(jwt.substr(pTag + 1, jwt.size() - pTag - 1));
    j.append("\"}");

    free(headers);

    json_error_t error;
    json_t *jwe = json_loads(j.c_str(), 0, &error);
    return jwe;
}
