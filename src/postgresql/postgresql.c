#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "libpq-fe.h"
#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>

#define _STDC_WANT_LIB_EXT__ 1
#define PRINT_DBG 1
#define LOG_FILE "dbg.log"

// TODOs:
// - use enums for error codes
// - write a command-line parser to handle arguments
// - create a group policy to run this program. currently only the postgres
//      user can run the program and access the postgres database.

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

// include this in a different header file
int
read_log_format(void)
{
    char command[] = "cat /opt/zeek/logs/current/conn.log|zeek-cut -m|head -n1";
    FILE* fp;
    char path[1035];

    fp = popen(command, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "failed to run command\n");
        return 1;
    }
    
    while (fgets(path, sizeof(path), fp) != NULL) 
    {
        printf("%s", path);
    }

    int exit_code = pclose(fp);

    return exit_code;
}

enum
{
    REJECT_DB_USERNAME_LENGTH = -100,
} CliError;

static void
exit_nicely(PGconn* conn_ptr)
{
    PQfinish(conn_ptr);
    exit(1);
}

int
string_length(const char* str)
{
    char* end = strchr(str, '\0');
    int length = (int)(char)(end - str) / sizeof(char);
    if (length > 29) return -2; 
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
    print_dbg("\tAccepted string: %s, length: %d", str,len);
    return 0;
}

// put this function in another header file for db operations
int
create_pgdb_if_exists(const char* db_name, const char* db_user, const char* db_pass)
{
    PGconn *conn = NULL;
    PGresult *result = NULL;
    const char* conninfo = NULL;
    char query[256];

    snprintf(conninfo, sizeof(conninfo), "user=%s password=%s dbname=%s",
            db_user, db_pass, db_name);

    conn = PQconnectdb(conninfo);
    if (PQstatus(conn) != CONNECTION_OK)
    {
        fprintf(stderr, "db connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }
    snprintf(query, sizeof(query), "SELECT 1 FROM pg_database WHERE datname='%s'", db_name);
    res = PQexec(conn, query);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) 
    {
        fprintf(stderr, "SELECT query failed: %s\n", PQerrorMessage(conn));
        PQclear(result);
        PQfinish(conn);
        return -1;
    }

    if (PQntuples(result) > 0) 
    {
        // Database already exists
        PQclear(result);
        PQfinish(conn);
        printf("Database '%s' already exists.\n", db_name);
        return 0;
    }

    PQclear(res);

    // Create the database
    snprintf(query, sizeof(query), "CREATE DATABASE %s", db_name);
    result = PQexec(conn, query);

    if (PQresultStatus(result) != PGRES_COMMAND_OK) 
    {
        fprintf(stderr, "CREATE DATABASE failed: %s\n", PQerrorMessage(conn));
        PQclear(result);
        PQfinish(conn);
        return -1;
    }

    PQclear(result);
    PQfinish(conn);

    printf("Database '%s' created successfully.\n", db_name);
    return 0;
}

int 
main(int argc, char **argv)
{
    const char* conn_info;
    PGconn* conn_ptr;
    //PGresult*   result = NULL; 
    //int         nFields;
    //int         i,j;

    read_log_format();

    if (argc > 1) 
    {
        // IDEA: check user-supplied name against list of known names.
        // For now, just check the length and if there of invalid characters.
        int len = string_length(argv[1]);

        if (len < 0 || sanitize_str(len, argv[1]) < 0) return -1;      

        conn_info = argv[1]; //"dbname = <database_name"

    } else { conn_info = "dbname = postgres"; }

    conn_ptr = PQconnectdb(conn_info);
    
    if (PQstatus(conn_ptr) != CONNECTION_OK)
    {
        printf("connection error: %s", PQerrorMessage(conn_ptr));
        exit_nicely(conn_ptr);
    } 

    printf("connect success\n");
    
    // TASKS to complete tomorrow:
    // 1) create schema for tables that will store the logs
    // 2) listen to source log directory files for changes.
    // 3) when change is detected, push new data into log tables
    // 4) use threading, easy.
    return 0;
}
