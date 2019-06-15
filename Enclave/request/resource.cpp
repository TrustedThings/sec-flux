#include "resource.h"

Resource::Resource()
{

}

Resource::~Resource()
{

}

string Resource::get_path()
{
    return mPath;
}

void Resource::set_path(string path)
{
    mPath = path;
}

int Resource::match(Request *request)
{
    string path1 = request->get_path();
    string delimiter = "/";
    string path2 = mPath;
    size_t pos1 = 0, pos2 = 0;
    string token1, token2;

    while(true)
    {
        pos1 = path1.find(delimiter);
        pos2 = path2.find(delimiter);
        // Different path lengths
        if(pos1 == string::npos ^ pos2 == string::npos){
            request->clear_path_parameters();
            return 0;
        }
        token1 = path1.substr(0, pos1);
        token2 = path2.substr(0, pos2);

        // Path parameter
        if(token2.rfind("{", 0) == 0) {
            
            request->set_path_parameter(
                token2.substr(1, token2.length() - 2), 
                token1    
            );
        } else {
            // Mismatch
            if(token1.compare(token2) != 0) {
                request->clear_path_parameters();
                return 0;
            }
        }
        // Check path end
        if(pos1 == string::npos && pos2 == string::npos){
            return 1;
        }

        path1.erase(0, pos1 + delimiter.length());
        path2.erase(0, pos2 + delimiter.length());
    }
}

void Resource::set_handler(string method, Handler handler)
{
    mHandlers.emplace(method, handler);
}

void Resource::handle(sqlite3 **db, Request *request)
{
    string method = request->get_method();
    Handler handler = mHandlers[method];
    (handler)(db, request);
}
