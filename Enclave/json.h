#include <jansson.h>
#include "error/error.h"

#define JSON_LABEL_MESSAGE  "msg"
#define JSON_LABEL_IV       "iv"
#define JSON_LABEL_TAG      "tag"

int json_add_string(json_t *json, const char *key, const char *value);
int json_add_bin2b64url_string(json_t *json, const char *key, unsigned char *value, int valueLen);

void json_print(json_t *json);
void json_test(json_t *json, const char *message);

unsigned char *json_to_unsigned_char(json_t *json, int flags);
unsigned char *json_to_unsigned_char(json_t *json, int *len, int flags);

int json_parse_and_set_new(json_t *json, const char *key, const char *value);
int json_parse_and_set_new(json_t *json, const char *key, const unsigned char *value);

json_t *jwt2jwe(char *jwtIn);