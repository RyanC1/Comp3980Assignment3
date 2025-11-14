#include "../include/util.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

ssize_t safe_read(const int fd, void *buf, const size_t count, bool exact)
{
    uint8_t *p;
    size_t   total;
    ssize_t  n;

    p     = buf;
    total = 0;

    do
    {
        n = read(fd, p + total, count - total);
        if(n > 0)
        {
            total += (size_t)n;
        }
        else if(n == -1 && errno != EINTR)
        {
            if((errno == EAGAIN || !exact) && total > 0)
            {
                return (ssize_t)total;
            }
            return -1;
        }

    } while(total < count && n != 0);

    return (ssize_t)total;
}

ssize_t safe_write(int fd, const void *buf, size_t n)
{
    const uint8_t *p;
    size_t         left;

    p    = (const uint8_t *)buf;
    left = n;
    while(left > 0)
    {
        ssize_t w;
        w = write(fd, p, left);
        if(w > 0)
        {
            p += (size_t)w;
            left -= (size_t)w;
            continue;
        }
        if(w < 0 && errno == EINTR)
        {
            continue;
        }

        return -1;
    }
    return (ssize_t)n;
}

char *concat_string(const char *str1, const char *str2)
{
    size_t len = strlen(str1) + strlen(str2);

    char *result = (char *)malloc(len + 1);
    if(result == NULL)
    {
        return NULL;
    }

    snprintf(result, len, "%s%s", str1, str2);

    return result;
}

int create_un_socket()
{
    int socket_fd;

#ifdef SOCK_CLOEXEC
    socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);    // NOLINT(android-cloexec-socket)
#endif

    return socket_fd;
}

int init_un_addr(struct sockaddr_un *addr, const char *path)
{
    memset(addr, 0, sizeof(*addr));

    addr->sun_family = AF_UNIX;

    if(strlen(path) >= sizeof(addr->sun_path))
    {
        return -1;
    }

    strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);

    return 0;
}