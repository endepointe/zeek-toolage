#include <stdio.h>
#include <ctype.h>
#include "libpq-fe.h"
#include <assert.h>

enum
{
    REJECT_DB_USERNAME_LENGTH = -100,
} CliError;

int
string_length(const char* str)
{
    int length = 0;
    while (*str != '\0')
    {
        if (length > 29) return -2; //TODO: use enum for error codes
        length += 1;
        str++;
    }
    return length;
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
        if (len > 0)
        {
            for (int i = 0; i < len -1; i++)
            {
                if (isprint(argv[1][i]) == 0) {
                    argv[1] = NULL;
                    return -1;
                }
            }
            printf("valid input\n");
        }
    } else {
        return -1; // TODO
    }
    return 0;
}
