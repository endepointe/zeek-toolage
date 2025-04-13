#define _STDC_WANT_LIB_EXT__ 1
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "libpq-fe.h"
#include <assert.h>
#include <stdarg.h>

#define PRINT_DBG 1
#define LOG_FILE "dbg.log"

int print_dbg(const char* format, ...)
{
#ifdef PRINT_DBG
    FILE* fp = fopen(LOG_FILE, "a");
    if (fp == NULL) return -1;
    va_list args;
    va_start(args, format);
    vfprintf(fp, format, args);
    va_end(args);
    fprintf(fp,"\n");
    fclose(fp);
    return 0;
#endif   
    return 0;
}

enum
{
    REJECT_DB_USERNAME_LENGTH = -100,
} CliError;

int
string_length(const char* str)
{
    char* end = strchr(str, '\0');
    int length = (int)(char)(end - str) / sizeof(char);
    if (length > 29) return -2; //TODO: use enum for error codes
    return length;
}

int
sanitize_str(int len, char* str)
{
    print_dbg("Source: postgresql.c:sanitize_str:");
    for (int i = 0; i < len; i++)
    {
        if (isprint(str[i]) == 0) {
            str = NULL;
            return -1;
        }
    }
    print_dbg("Accepted string: %s ", str);
    return 0;
}

int 
main(int argc, char **argv)
{
    //const char* conn_info;
    //PGconn*     conn = NULL;
    //PGresult*   result = NULL; 
    //int         nFields;
    //int         i,j;

    if (argc > 1) 
    {
        // IDEA: check user-supplied name against list of known names.
        // For now, just check the length and if there of invalid characters.
        int len = string_length(argv[1]);
        print_dbg("Length: %d\n", len);

        if (len < 0 || sanitize_str(len, argv[1]) < 0)
        {
            return -1; //TODO: create return values     
        }
    } else {
        return -1; // TODO
    }
    return 0;
}
