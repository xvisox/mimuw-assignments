#ifndef SENDER_UTILITY_HPP
#define SENDER_UTILITY_HPP

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <cstdint>
#include <arpa/inet.h>

#include "../utils/err.h"
#include "../utils/const.h"
#include "../utils/types.h"

inline static int open_socket() {
    int socket_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) PRINT_ERRNO();
    return socket_fd;
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

inline static void send_packet(const struct sockaddr_in *send_address, int socket_fd,
                               byte_t *packet, packet_size_t packet_size) {
    auto address_length = (socklen_t) sizeof(*send_address);
    ssize_t sent_length;
    do {
        errno = 0;
        sent_length = sendto(socket_fd, packet, packet_size, NO_FLAGS,
                             (struct sockaddr *) send_address, address_length);
    } while (sent_length < 0);
    // Maybe this would be a better way to handle error.
    // if (sent_length < 0) PRINT_ERRNO();
}

#endif // SENDER_UTILITY_HPP