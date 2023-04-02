#ifndef SENDER_UTILITY_H
#define SENDER_UTILITY_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "err.h"

struct __attribute__((__packed__)) AudioPacket {
    uint64_t session_id;
    uint64_t first_byte_num;
    char audio_data[];
};

inline static uint16_t read_port(char *string) {
    errno = 0;
    unsigned long port = strtoul(string, NULL, 10);

    PRINT_ERRNO();
    if (port > UINT16_MAX) {
        fatal("%ul is not a valid port number", port);
    }

    return (uint16_t) port;
}

inline static uint64_t read_size(char *string) {
    errno = 0;
    char *endptr;
    unsigned long long size = strtoull(string, &endptr, 10);

    PRINT_ERRNO();
    if (*endptr != '\0') {
        fatal("Invalid size: %s", string);
    }

    return (uint64_t) size;
}

inline static struct sockaddr_in get_send_address(char *host, uint16_t port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *address_result;
    CHECK(getaddrinfo(host, NULL, &hints, &address_result));

    struct sockaddr_in send_address;
    send_address.sin_family = AF_INET; // IPv4
    send_address.sin_addr.s_addr =
            ((struct sockaddr_in *) (address_result->ai_addr))->sin_addr.s_addr; // IP address
    send_address.sin_port = htons(port);

    freeaddrinfo(address_result);

    return send_address;
}

inline static void send_packet(const struct sockaddr_in *send_address, int socket_fd,
                               struct AudioPacket *packet, size_t packet_size) {
    socklen_t address_length = (socklen_t) sizeof(*send_address);
    int flags = 0;
    errno = 0;
    ssize_t sent_length = sendto(socket_fd, packet, packet_size, flags,
                                 (struct sockaddr *) send_address, address_length);
    if (sent_length < 0) {
        PRINT_ERRNO();
    }
    ENSURE(sent_length == packet_size);
}

#endif // SENDER_UTILITY_H