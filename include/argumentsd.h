#ifndef ARGUMENTSD_H
#define ARGUMENTSD_H

struct argumentsd
{
    int argc;
    const char *program_name;
    const char *socket_path;
    char **argv;
};

#endif    // ARGUMENTSD_H
