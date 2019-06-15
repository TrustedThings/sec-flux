#ifndef ERRORABLE_H
#define ERRORABLE_H

#include "error.h"

class Errorable{
  public:
    Errorable();

    int err(const char *message, enum error_code code);

    error_t *get_error();

    void print_error();

    error_t mError;
};


#endif
