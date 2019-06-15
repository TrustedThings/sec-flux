#include "data_manager.h"
#include "sgx_tseal.h"
#include "sgx_attributes.h"
#include "sgx_key.h"
#include "../Enclave_t.h"
#include "app_owner.h"
using namespace std;

DataManager::DataManager()
{
  
}

DataManager::~DataManager()
{
  sqlite3_close(mDb);
}

int DataManager::init(const char *name)
{
  int res;
  mName = name;
  mFileName = "data/db.seal";
  res = sqlite3_open(":memory:", &mDb);
  // Try to load database backup
  if(unseal_db(mDb)) {
    sqlite3_stmt *statement;
    size_t current, previous = 0;
    current = mDump.find('\n');
    while(current != string::npos) {
        //printf("partial: %s\n", mDump.substr(previous, current - previous).c_str());
        sqlite3_prepare_v2(mDb, mDump.substr(previous, current - previous).c_str(), -1, &statement, NULL);
        sqlite3_step(statement);
        sqlite3_finalize(statement);
        previous = current + 1;
        current = mDump.find('\n', previous);
    }
    /*
    if(res != SQLITE_DONE) {
        printf("could not load database!\n");
        printf("res: %d\n", res);
    }*/
    //dump_db(mDb);
    //printf("redump: %s\n", mDump.c_str());
    
  } else {  
    // Create new database
    res = create_tables();
    seal_db();
  }

  // Create session counter
  // TODO: Check if exists
  /*const char *request = "INSERT INTO sessions_count (id, counter) VALUES (1,0);";
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  res = sqlite3_step(statement);
  sqlite3_finalize(statement);
  */

  return 1;
}


sqlite3 **DataManager::get_db_ptr()
{
  return &mDb;
}

int DataManager::create_table(const char *request)
{
  int ret;
  sqlite3_stmt *statement;
  sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
  ret = sqlite3_step(statement);
  if(ret != SQLITE_DONE){
    printf("error creating table!\n");
    sqlite3_finalize(statement);
    return 0;
  }
  sqlite3_finalize(statement);
  return 1;
}

int DataManager::create_tables()
{
  int ret;
  string adminRequest = "INSERT OR IGNORE INTO clients (id, name, pub_key_x_hex, pub_key_y_hex, is_admin, is_active) VALUES (1, '";
  adminRequest.append(OWNER_NAME);
  adminRequest.append("', '");
  adminRequest.append(OWNER_PUB_KEY_X);
  adminRequest.append("', '");
  adminRequest.append(OWNER_PUB_KEY_Y);
  adminRequest.append("', 1, 1);");
  
  string requests[] = {
    "CREATE TABLE IF NOT EXISTS action_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, message TEXT NOT NULL, timestamp TEXT NOT NULL, action_template_id INTEGER NOT NULL, event_id INTEGER NOT NULL, rule_id INTEGER NOT NULL);",
    "CREATE TABLE IF NOT EXISTS action_templates (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, rule_id INTEGER NOT NULL, function TEXT NOT NULL, context TEXT NOT NULL, action_type_id INTEGER NOT NULL);",
    "CREATE TABLE IF NOT EXISTS action_template_clients (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER NOT NULL, action_template_id INTEGER NOT NULL);",
    "CREATE TABLE IF NOT EXISTS action_types (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, schema TEXT NOT NULL);",
    "CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY AUTOINCREMENT, name text NOT NULL, is_admin INTEGER NOT NULL, is_active INTEGER NOT NULL, pub_key_x_hex text NOT NULL, pub_key_y_hex text NOT NULL);",
    "CREATE TABLE IF NOT EXISTS contexts (id INTEGER PRIMARY KEY AUTOINCREMENT, value text NOT NULL)",
    "INSERT OR IGNORE INTO contexts(id, value) VALUES(1, '{}')",
    "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER NOT NULL, event_type_id INTEGER NOT NULL, properties TEXT NOT NULL, timestamp TEXT NOT NULL);",
    "CREATE TABLE IF NOT EXISTS event_types (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, schema TEXT NOT NULL);",
    "CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, function TEXT NOT NULL, context NOT NULL, event_type_id INTEGER NOT NULL, is_active INTEGER NOT NULL);",
    "CREATE TABLE IF NOT EXISTS sessions_count (id INTEGER PRIMARY KEY, counter INTEGER NOT NULL);",
    "INSERT OR IGNORE INTO sessions_count (id, counter) VALUES (1,0);",
    "CREATE TABLE IF NOT EXISTS versions (id INTEGER PRIMARY KEY, version INTEGER NOT NULL);",
    "INSERT OR IGNORE INTO versions (id, version) VALUES (1,1);",
    adminRequest,
  };
  int nRequests = sizeof(requests) / sizeof(requests[0]);

  for(int i = 0; i < nRequests; i++){
    ret = create_table((requests[i]).c_str());
    if(ret != 1) return 0;
  }
  return 1;
}


int DataManager::dump_db(sqlite3 *db)
{

    //FILE *fp = NULL;

    sqlite3_stmt *stmt_table = NULL;
    sqlite3_stmt *stmt_data = NULL;

    string tableName;
    string data;
    int col_cnt = 0;

    int ret = 0;
    int index = 0;
    string cmd;
    mDump = "";

    ret = sqlite3_prepare_v2 (db, "SELECT sql,tbl_name FROM sqlite_master WHERE type = 'table';",
    -1, &stmt_table, NULL);
    if (ret != SQLITE_OK)
    goto EXIT;


    ret = sqlite3_step (stmt_table);
    while (ret == SQLITE_ROW){
        data = (const char *)sqlite3_column_text(stmt_table, 0);
        tableName = (const char *)sqlite3_column_text(stmt_table, 1);
        if (data.empty() || tableName.empty()){
            ret = -1;
            goto EXIT;
        }

        /* CREATE TABLE statements */
        mDump.append(data + ";\n");

        /* fetch table data */
        if(tableName.compare("events") == 0 || tableName.compare("action_messages") == 0) {
        } else {
            cmd= "SELECT * from " + tableName + ";";

            ret = sqlite3_prepare_v2 (db, cmd.c_str(), -1, &stmt_data, NULL);
            if (ret != SQLITE_OK)
                goto EXIT;

            ret = sqlite3_step (stmt_data);
            while (ret == SQLITE_ROW){
                mDump.append("INSERT INTO \"" + tableName + "\" VALUES(");
                col_cnt = sqlite3_column_count(stmt_data);
                for (index = 0; index < col_cnt; index++)
                {
                    if (index)
                        mDump.append(",");
                    data = (const char *)sqlite3_column_text (stmt_data, index);

                    if (!data.empty()){
                        if (sqlite3_column_type(stmt_data, index) == SQLITE_TEXT){
                            mDump.append("'" + data + "'");
                        }
                        else{
                            mDump.append(data);
                        }
                    }
                    else
                        mDump.append("NULL");
                }
                mDump.append(");\n");
                ret = sqlite3_step (stmt_data);
            }
        }

        ret = sqlite3_step (stmt_table);
    }

    /* Triggers */
    if (stmt_table)
        sqlite3_finalize (stmt_table);

    ret = sqlite3_prepare_v2 (db, "SELECT sql FROM sqlite_master WHERE type = 'trigger';",
    -1, &stmt_table, NULL);
    if (ret != SQLITE_OK)
        goto EXIT;

    ret = sqlite3_step (stmt_table);
    while (ret == SQLITE_ROW){
    data = (const char *)sqlite3_column_text (stmt_table, 0);
        if (data.empty()){
            ret = -1;
            goto EXIT;
        }

        /* CREATE TABLE statements */
        mDump.append(data + ";\n");

        ret = sqlite3_step (stmt_table);
    }

    EXIT:
    if (stmt_data)
        sqlite3_finalize (stmt_data);
    if (stmt_table)
        sqlite3_finalize (stmt_table);
    return 1;
}

int DataManager::archive_event(const char *dump, const char *filename)
{
    sgx_attributes_t attribute_mask;
    sgx_status_t res;
    attribute_mask.flags = 0xFF0000000000000B;
    attribute_mask.xfrm = 0x0;
    uint32_t plaintext_len = strlen(dump) + 1;
    uint32_t ciph_size = sgx_calc_sealed_data_size(0, plaintext_len);
    char *sealed = (char *) malloc(ciph_size);
    res = sgx_seal_data_ex(
        0x0001,
        attribute_mask,
        0xF0000000,
        0,
        NULL,
        plaintext_len,
        (uint8_t *)dump,
        ciph_size,
        (sgx_sealed_data_t *)sealed
    );
    ocall_save_data(sealed, ciph_size, filename);
    return 1;
}

int DataManager::increment_version()
{
    int res;
    const char *request = "UPDATE versions SET version = version + 1;";
    sqlite3_stmt *statement;
    sqlite3_prepare_v2(mDb, request, -1, &statement, NULL);
    res = sqlite3_step(statement);
    sqlite3_finalize(statement);
    return 1;
}

int DataManager::seal_db()
{
    dump_db(mDb);
    sgx_attributes_t attribute_mask;
    sgx_status_t res;
    attribute_mask.flags = 0xFF0000000000000B;
    attribute_mask.xfrm = 0x0;
    uint32_t plaintext_len = mDump.size() + 1;
    //printf("dumping: %s\n", mDump.c_str());
    uint32_t ciph_size = sgx_calc_sealed_data_size(0, plaintext_len);
    char *sealed = (char *) malloc(ciph_size);
    res = sgx_seal_data_ex(
        0x0001,
        attribute_mask,
        0xF0000000,
        0,
        NULL,
        plaintext_len,
        (uint8_t *)mDump.c_str(),
        ciph_size,
        (sgx_sealed_data_t *)sealed
    );
    ocall_save_data(sealed, ciph_size, mFileName);
    return 1;
}

int DataManager::unseal_db(sqlite3 *db)
{
    sgx_status_t res;
    size_t s;
    res = ocall_get_data_size(mFileName, &s);
    if(s == 0) return 0;
    uint8_t *sealed = (uint8_t *)malloc(s);
    res = ocall_load_data((char *)sealed, s, mFileName);
    uint32_t pl_len = sgx_get_encrypt_txt_len((sgx_sealed_data_t *)sealed);
    uint8_t *pl = (uint8_t *)malloc(pl_len);
    res = sgx_unseal_data(
        (sgx_sealed_data_t *)sealed,
        NULL,
        0,
        pl,
        &pl_len
    );
    mDump = (char *)pl;
    free(pl);
    return 1;
}