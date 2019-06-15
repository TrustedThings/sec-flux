#include "stdio.h"
#include "Enclave_t.h"
#include <string>

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

void to_upper(char *w)
{
    for(int i=0; i<strlen((const char *)w); i++){
        w[i] = toupper(w[i]);
    }
}

void to_upper(unsigned char *w)
{
    to_upper((char *) w);
}