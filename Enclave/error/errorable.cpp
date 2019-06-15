#include "errorable.h"

Errorable::Errorable()
{
  error_init(&mError);
}

int Errorable::err(const char *message, enum error_code code)
{
  error_set(&mError, message, code);
  return 0;
}

error_t *Errorable::get_error()
{
  if(has_error(&mError)){
    return &mError;
  } else{
    return NULL;
  }
}

void Errorable::print_error()
{
  if(has_error(&mError)){
    error_print(&mError);
  } else{
    printf("no error\n");
  }
}
