#ifndef SIKRADIO_COMMON_H
#define SIKRADIO_COMMON_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <cstdint>
#include <arpa/inet.h>

#include "err.h"

inline static int open_socket() {
    int socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) PRINT_ERRNO();

    return socket_fd;
}

#endif // SIKRADIO_COMMON_H