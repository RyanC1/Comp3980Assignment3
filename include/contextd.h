#ifndef CONTEXTD_H
#define CONTEXTD_H
#include <sys/poll.h>

struct contextd
{
    struct argumentsd *arguments;

    int socket_fd;

    int           *client_sockets;
    nfds_t         max_clients;
    struct pollfd *fds;

    int exit_code;
};

#endif    // CONTEXTD_H
