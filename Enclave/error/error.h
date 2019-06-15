#ifndef ERROR_H
#define ERROR_H

#include "../utils.h"
#include "stdio.h"

#define ERROR_TEXT_LENGTH 160

enum error_code {
    error_misc,
    error_string_not_json,
    error_bad_client_id,
    error_missing_field,
    error_json_missing_field,
    error_json_wrong_type,
    error_no_ciphertext,
    error_no_plaintext
};

typedef struct error_t {
    char text[ERROR_TEXT_LENGTH];
    char code;
    bool has_error;
} error_t;


void error_init(error_t *error);

void error_set(error_t *error, const char *text, enum error_code code);

void error_print(error_t *error);
bool has_error(error_t *error);

#endif
