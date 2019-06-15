#include "http_responses.h"

void http_success(Request *request, json_t *json)
{
    char *message = json_dumps(json, JSON_COMPACT);
    http_success(request, message);
    free(message);
    json_decref(json);
}

void http_success(Request *request, string response)
{
    request->set_response_message(response);
    request->set_status_code(200);
}

void http_created(Request *request, json_t *json)
{
    char *message = json_dumps(json, JSON_COMPACT);
    http_created(request, message);
    free(message);
    json_decref(json);
}

void http_created(Request *request, string response)
{
    request->set_response_message(response);
    request->set_status_code(201);
}

void http_no_content(Request *request)
{
    request->set_status_code(204);
}

void http_unauthorized(Request *request, string response)
{
    http_unauthorized(request);
    request->set_response_string(response);
}

void http_unauthorized(Request *request)
{
    request->set_status_code(401);
    request->set_response_string("Unauthorized");
}

void http_forbidden(Request *request, string response)
{
    http_forbidden(request);
    request->set_response_message(response);
}

void http_forbidden(Request *request)
{
    request->set_status_code(403);
    request->set_response_message("Forbidden");
}

void http_client_error(Request *request, string response)
{
    http_client_error(request);
    request->set_response_message(response);
}

void http_client_error(Request *request)
{
    request->set_status_code(400);
    request->set_response_message("Payload error");
}

void http_not_found(Request *request, string response)
{
    http_not_found(request);
    request->set_response_message(response);
}

void http_not_found(Request *request)
{
    request->set_status_code(404);
    request->set_response_message("Not found");
}

void http_server_error(Request *request)
{
    request->set_status_code(500);
    request->set_response_message("Server error");
}