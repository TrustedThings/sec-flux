#include "duktape.h"
#include "utils.h"

bool duk_eval_rule(const char *function, const char *event, char **localContext, char **globalContext);
char *duk_eval_template(const char *function, const char *event, char **localContext, char **globalContext);

char *my_duk_get_prop(duk_context *ctx, const char *name);

int duk_compile_js(duk_context *ctx, const char *programBody);

bool duk_eval_global_context(const char *function, char **globalContext);