#include "action_template_client.h"
#include "../utils.h"
#include "models.h"
#include <string>

using namespace std;

int MActionTemplateClient::create_by_action_template_id(sqlite3 **db, int actionTemplateId, json_t *clients)
{
    int ret;
    if(json_typeof(clients) != JSON_ARRAY) return 0;

    string request = "INSERT INTO action_template_clients (action_template_id, client_id) VALUES ";

    int clientId;
    json_t *client;
    for(int i = 0; i < json_array_size(clients); i++) {
        client = json_array_get(clients, i);
        ret = json_unpack_ex(client, NULL, JSON_STRICT, "{s:i}", "id", &clientId);
        if(ret == -1) {
            return 0;
        }
        request += "(" + to_string(actionTemplateId) + ", " + to_string(clientId) + "),";
    }
    request.pop_back();
    request += ";";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request.c_str(), -1, &statement, NULL);
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return ret == SQLITE_DONE;
}

json_t *MActionTemplateClient::get_by_action_template_id(sqlite3 **db, int actionTemplateId)
{
    json_t *json = json_array();
    int ret;
    const char *request = "SELECT client_id FROM action_template_clients WHERE action_template_id = ?;";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    sqlite3_bind_int(statement, 1, actionTemplateId);
    ret = sqlite3_step(statement);
    while(ret == SQLITE_ROW) {
        json_t *client = json_pack("{s:i}", "id", sqlite3_column_int(statement, 0));
        json_array_append_new(json, client);
        ret = sqlite3_step(statement);
    }
    sqlite3_finalize(statement);
    return json;
}

int MActionTemplateClient::update_by_action_template_id(sqlite3 **db, int actionTemplateId, json_t *clients)
{
    if(delete_by_action_template_id(db, actionTemplateId) != 1) {
        return 0;
    }
    return create_by_action_template_id(db, actionTemplateId, clients);
}

int MActionTemplateClient::delete_by_action_template_id(sqlite3 **db, int actionTemplateId)
{
    int ret;
    const char *request = "DELETE FROM action_template_clients WHERE action_template_id = ?;";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(*db, request, -1, &statement, NULL);
    sqlite3_bind_int(statement, 1, actionTemplateId);
    ret = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return ret == SQLITE_DONE;
}

