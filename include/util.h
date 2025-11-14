#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <sys/un.h>
#include <unistd.h>

/**
 * Safely reads count bytes from the given file descriptor or until eof.
 * Returns the number of characters read or -1 if an error occurs.
 * Setting exact to true will prevent non-blocking io from returning
 * a value, instead returning -1.
 *
 * @param fd the file descriptor to read from
 * @param buf where to read too
 * @param count bytes to read
 * @param exact if non-blocking fds should return the number of bytes read or -1
 * @return number of bytes read or -1
 */
ssize_t safe_read(int fd, void *buf, size_t count, bool exact);

/**
 * Writes n bytes from buf to the given fd.
 * Will return n or -1 if not all the bytes were written.
 * @param fd the file to write to
 * @param buf the buffer to pull from
 * @param n the number of bytes to write
 * @return n or -1 if partial write
 */
ssize_t safe_write(int fd, const void *buf, size_t n);

char * concat_string(const char * str1, const char * str2);

int create_un_socket(void);

int init_un_addr(struct sockaddr_un *addr, const char *path);

#endif    // UTIL_H
