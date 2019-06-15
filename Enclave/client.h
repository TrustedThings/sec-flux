#include <string>
#include "database/sqlite3.h"

using namespace std;

void test_post_in(string uri);
void test_get_in(string uri);

void test_in(string method, string uri);
void test_out();


void test_create_client();