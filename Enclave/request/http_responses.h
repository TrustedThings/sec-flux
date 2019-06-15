#include "request.h"

void http_success(Request *request, json_t *json);
void http_success(Request *request, string response);

void http_created(Request *request, json_t *json);
void http_created(Request *request, string response);

void http_no_content(Request *request);

void http_unauthorized(Request *request, string response);
void http_unauthorized(Request *request);

void http_forbidden(Request *request, string response);
void http_forbidden(Request *request);

void http_client_error(Request *request, string response);
void http_client_error(Request *request);

void http_not_found(Request *request, string response);
void http_not_found(Request *request);

void http_server_error(Request *request);