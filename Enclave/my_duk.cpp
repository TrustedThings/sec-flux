#include "my_duk.h"
#include <string>

using namespace std;

bool duk_eval_rule(const char *function, const char *event, char **localContext, char **globalContext)
{
    duk_bool_t duk_ret = 0;
    string fun = function;
    string str = "function rule(event) {" + fun + "}";

    duk_context *ctx = duk_create_heap_default();
    // Set context
    string context = "{\"global\":" + string(*globalContext) + ",\"local\":" + string(*localContext) + "}";
    duk_push_string(ctx, context.c_str());
    duk_json_decode(ctx, -1);
    duk_put_global_string(ctx, "context");

    // Set function
    if(duk_compile_js(ctx, str.c_str())) {
        duk_get_global_string(ctx, "rule");
        duk_push_string(ctx, event);
        duk_json_decode(ctx, -1);
        if(duk_pcall(ctx, 1) != DUK_EXEC_SUCCESS) {
            duk_destroy_heap(ctx);
            return false;
            //duk_get_prop_string(ctx, -1, "stack");
            //printf("error evaluating rule: %s\n", duk_safe_to_string(ctx, -1));
        } else {
            duk_ret = duk_get_boolean(ctx, -1);
        }
    } else {
        duk_destroy_heap(ctx);
        return false;
        //printf("could not compile js!\n");
    }

    // Get context variables
    duk_get_global_string(ctx, "context");
    char *tmp;

    tmp = my_duk_get_prop(ctx, "global");
    if(tmp == NULL) {
        duk_destroy_heap(ctx);
        return false;
    }
    delete[] *globalContext;
    *globalContext = tmp;

    tmp = my_duk_get_prop(ctx, "local");
    if(tmp == NULL) {
        duk_destroy_heap(ctx);
        return false;
    }
    delete[] *localContext;
    *localContext = tmp;

    duk_destroy_heap(ctx);
    return duk_ret;
}

char *my_duk_get_prop(duk_context *ctx, const char *name)
{
    duk_push_string(ctx, name);
    int v = duk_get_prop(ctx, -2);
    if(!v) {
        duk_pop(ctx);
        return NULL;
    }
    const char *tmp = duk_json_encode(ctx, -1);
    duk_pop(ctx);
    char *ret = new char[strlen(tmp) + 1];
    memcpy(ret, tmp, strlen(tmp) + 1);
    return ret;
}

char *duk_eval_template(const char *function, const char *event, char **localContext, char **globalContext)
{
    char *duk_ret;
    string fun = function;
    string templ = "function templ(ev) {function inner(event) {" + fun + "} return JSON.stringify(inner(ev));}";
    duk_context *ctx = duk_create_heap_default();
    // Set context
    string context = "{\"global\":" + string(*globalContext) + ",\"local\":" + string(*localContext) + "}";
    duk_push_string(ctx, context.c_str());
    duk_json_decode(ctx, -1);
    duk_put_global_string(ctx, "context");
    // Set function
    if(duk_compile_js(ctx, templ.c_str())) {
        duk_get_global_string(ctx, "templ");
        duk_push_string(ctx, event);
        duk_json_decode(ctx, -1);
        if(duk_pcall(ctx, 1) == DUK_EXEC_SUCCESS) {
            const char *r = duk_get_string(ctx, -1);
            if(r == NULL) {
                duk_destroy_heap(ctx);
                return NULL;
            }
            int l = strlen(r);
            duk_ret = new char[l + 1];
            memcpy(duk_ret, r, l+1);
        } else {
            duk_destroy_heap(ctx);
            return NULL;
            //duk_get_prop_string(ctx, -1, "stack");
            //printf("error evaluating template: %s\n", duk_safe_to_string(ctx, -1));
        }
    } else {
        duk_destroy_heap(ctx);
        return NULL;
        //printf("could not compile js!\n");
    }

    // Get context variables
    duk_get_global_string(ctx, "context");
    char *tmp;

    tmp = my_duk_get_prop(ctx, "local");
    if(tmp == NULL) {
        duk_destroy_heap(ctx);
        return NULL;
    }
    delete[] *localContext;
    *localContext = tmp;

    tmp = my_duk_get_prop(ctx, "global");
    if(tmp == NULL) {
        duk_destroy_heap(ctx);
        return NULL;
    }
    delete[] *globalContext;
    *globalContext = tmp;

    duk_destroy_heap(ctx);
    return duk_ret;
}

int duk_compile_js(duk_context *ctx, const char *programBody)
{
    int ret;
    if(duk_pcompile_string(ctx, 0, programBody) != 0) {
        printf("compile failed!\n");
        ret = 0;
    }
    else {
        duk_pcall(ctx, 0);
        ret = 1;
    }
    duk_pop(ctx);
    return ret;
}

bool duk_eval_global_context(const char *function, char **globalContext)
{
    string templ = "function ev() {" + string(function) + "}";
    duk_context *ctx = duk_create_heap_default();
    // Set context
    string context = "{\"global\":" + string(*globalContext) + "}";
    duk_push_string(ctx, context.c_str());
    duk_json_decode(ctx, -1);
    duk_put_global_string(ctx, "context");
    // Set function 
    if(duk_compile_js(ctx, templ.c_str())) {
        duk_get_global_string(ctx, "ev");
        if(duk_pcall(ctx, 0) != DUK_EXEC_SUCCESS) {
            duk_destroy_heap(ctx);
            return false;
        }

    } else {
        duk_destroy_heap(ctx);
        return false;
    }

    // Get context variables
    duk_get_global_string(ctx, "context");
    char *tmp;

    tmp = my_duk_get_prop(ctx, "global");
    if(tmp == NULL) {
        duk_destroy_heap(ctx);
        return false;
    }
    delete[] *globalContext;
    *globalContext = tmp;

    duk_destroy_heap(ctx);
    return true;
}