#ifndef CONTEXT_H
#define CONTEXT_H
#include <sys/un.h>

struct context
{
    struct arguments *arguments;

    struct sockaddr_un addr;

    unsigned int min_delay;
    unsigned int max_delay;

    int exit_code;
};

#endif    // CONTEXT_H
