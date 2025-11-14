#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <stdbool.h>

struct arguments
{
    int         argc;
    char      **argv;
    const char *program_name;

    const char  *server_path;
    const char  *min_delay_str;
    const char  *max_delay_str;
    int          num_files;
    char **files;
};

#endif    // ARGUMENTS_H
