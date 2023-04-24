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
#include <netdb.h>
#include "../utils/err.h"
#include "../utils/const.h"
#include "../utils/types.h"

inline static int bind_socket(port_t port, in_addr_t address) {
    // Creating IPv4 UDP socket.
    int socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ENSURE(socket_fd > 0);

    struct sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = address;
    server_address.sin_port = htons(port);

    // Bind the socket to a concrete address.
    CHECK_ERRNO(bind(socket_fd, (struct sockaddr *) &server_address,
                     (socklen_t) sizeof(server_address)));

    return socket_fd;
}

inline static size_t read_message(int socket_fd, byte_t *buffer, size_t max_length) {
    ssize_t read_length;
    auto empty_packet_size = (ssize_t) (sizeof(session_id_t) + sizeof(packet_id_t));
    do {
        errno = 0;
        read_length = recv(socket_fd, buffer, max_length, NO_FLAGS);
        // Maybe this would be a better way to handle error.
        // if (len < 0) PRINT_ERRNO();
    } while (read_length <= empty_packet_size);
    return (size_t) read_length;
}

inline static struct sockaddr_in get_address(char const *host, port_t port) {
    struct addrinfo hints{};
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *address_result;
    CHECK(getaddrinfo(host, nullptr, &hints, &address_result));

    struct sockaddr_in send_address{};
    send_address.sin_family = AF_INET;
    send_address.sin_addr.s_addr = ((struct sockaddr_in *) (address_result->ai_addr))->sin_addr.s_addr;
    send_address.sin_port = htons(port);

    freeaddrinfo(address_result);
    return send_address;
}

#endif // RECEIVER_UTILITY_HPP