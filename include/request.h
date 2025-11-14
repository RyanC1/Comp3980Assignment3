#ifndef REQUEST_H
#define REQUEST_H
#include <pthread.h>
#include <stdatomic.h>

struct request
{
    struct sockaddr_un *addr;

    unsigned int *min_delay;
    unsigned int *max_delay;

    char *filepath;
    pthread_mutex_t *print_mutex;
    atomic_size_t *failed_threads;
};

#endif    // REQUEST_H
