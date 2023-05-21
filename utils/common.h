#ifndef SIKRADIO_COMMON_H
#define SIKRADIO_COMMON_H

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <cstdint>
#include <netdb.h>
#include "../utils/err.h"
#include "../utils/const.h"
#include "../utils/types.h"

inline static socket_t open_udp_socket() {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        PRINT_ERRNO();
    }
    return socket_fd;
}

inline static socket_t open_multicast_socket() {
    int socket_fd = open_udp_socket();

    // Enable broadcasting
    int optval = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof optval) < 0)
        PRINT_ERRNO();
    // Set time to live
    int ttl = MAX_TTL;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl) < 0)
        PRINT_ERRNO();

    return socket_fd;
}

inline static socket_t open_listener_socket() {
    int socket_fd = open_udp_socket();

    // Enable reusing address
    int optval = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval) < 0)
        PRINT_ERRNO();

    return socket_fd;
}

inline static void connect_socket(socket_t socket_fd, const struct sockaddr_in *address) {
    CHECK_ERRNO(connect(socket_fd, (struct sockaddr *) address, sizeof(*address)));
}

inline static void bind_socket(socket_t socket_fd, const struct sockaddr_in *address) {
    CHECK_ERRNO(bind(socket_fd, (struct sockaddr *) address, sizeof(*address)));
}

inline static struct sockaddr_in get_remote_address(char const *host, port_t port, bool check_multicast) {
    struct sockaddr_in remote_address{};
    remote_address.sin_family = AF_INET;
    remote_address.sin_port = htons(port);

    if (check_multicast && !IN_MULTICAST(ntohl(inet_addr(host))))
        fatal("Given parameter is not a multicast address");

    if (inet_aton(host, &remote_address.sin_addr) == 0)
        fatal("Failed to convert address to binary form");

    return remote_address;
}

inline static struct sockaddr_in get_listener_address(port_t port) {
    struct sockaddr_in listener_address{};
    listener_address.sin_family = AF_INET;
    listener_address.sin_port = htons(port);
    listener_address.sin_addr.s_addr = htonl(INADDR_ANY);
    return listener_address;
}

#endif //SIKRADIO_COMMON_H