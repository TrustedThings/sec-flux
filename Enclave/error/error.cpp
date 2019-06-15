#include "error.h"

void error_init(error_t *error)
{
  error->text[0] = '\0';
  error->has_error = false;
}

void error_set(error_t *error, const char *text, enum error_code code)
{
  snprintf(error->text, ERROR_TEXT_LENGTH - 1, "%s", text);
  error->text[ERROR_TEXT_LENGTH - 1] = '\0';
  error->code = code;
  error->has_error = true;
}

void error_print(error_t *error)
{
  printf("Error code %d: %s\n", error->code, error->text);
}

bool has_error(error_t *error)
{
  return error->has_error;
}
