#ifndef RECEIVER_UTILITY_HPP
#define RECEIVER_UTILITY_HPP

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <cstdint>
#include "../utils/err.h"
#include "../utils/const.h"

int bind_socket(uint16_t port) {
    // Creating IPv4 UDP socket.
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ENSURE(socket_fd > 0);
    // After socket() call; we should close(sock) on any execution path.

    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET; // IPv4
    server_address.sin_addr.s_addr = htonl(INADDR_ANY); // Listening on all interfaces.
    server_address.sin_port = htons(port);

    // Bind the socket to a concrete address.
    CHECK_ERRNO(bind(socket_fd, (struct sockaddr *) &server_address,
                     (socklen_t) sizeof(server_address)));

    return socket_fd;
}

size_t read_message(int socket_fd, struct sockaddr_in *client_address, char *buffer, size_t max_length) {
    auto address_length = (socklen_t) sizeof(*client_address);
    errno = 0;
    ssize_t len = recvfrom(socket_fd, buffer, max_length, NO_FLAGS,
                           (struct sockaddr *) client_address, &address_length);

    if (len < 0) PRINT_ERRNO();
    return (size_t) len;
}

#endif // RECEIVER_UTILITY_HPP