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
#include <string>
#include <boost/algorithm/string.hpp>

#include "../utils/err.h"
#include "../utils/const.h"
#include "../utils/types.h"

inline static int open_udp_socket() {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        PRINT_ERRNO();
    }
    return socket_fd;
}

inline static int open_multicast_socket() {
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

inline static int open_listener_socket() {
    int socket_fd = open_udp_socket();

    // Enable reusing address
    int optval = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval) < 0)
        PRINT_ERRNO();

    return socket_fd;
}

inline static void bind_socket(int socket_fd, const struct sockaddr_in *address) {
    CHECK_ERRNO(bind(socket_fd, (struct sockaddr *) address, sizeof(*address)));
}

inline static struct sockaddr_in get_remote_address(char const *host, port_t port) {
    struct sockaddr_in remote_address{};
    remote_address.sin_family = AF_INET;
    remote_address.sin_port = htons(port);

    if (!IN_MULTICAST(ntohl(inet_addr(host))))
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

inline static void send_packet(int socket_fd, byte_t *packet, packet_size_t packet_size) {
    ssize_t sent_length;
    do {
        errno = 0;
        sent_length = send(socket_fd, packet, packet_size, NO_FLAGS);
        // Maybe this would be a better way to handle error.
        // if (sent_length < 0) PRINT_ERRNO();
    } while (sent_length < 0);
}

inline static void connect_socket(int socket_fd, const struct sockaddr_in *address) {
    CHECK_ERRNO(connect(socket_fd, (struct sockaddr *) address, sizeof(*address)));
}

inline static std::vector<packet_id_t> parse_rexmit(byte_t *buffer, ssize_t length) {
    buffer[length] = '\0';
    std::string str(reinterpret_cast<char *>(buffer));

    std::vector<std::string> parsable;
    boost::split(parsable, str, boost::is_any_of(", "));

    std::vector<packet_id_t> packets;
    for (auto it = std::next(parsable.begin()); it != parsable.end(); it++) {
        packet_id_t missed_id;
        try {
            missed_id = stoll(*it);
        } catch (std::invalid_argument &e) {
            continue;
        } catch (std::out_of_range &e) {
            continue;
        }
        packets.push_back(missed_id);
    }
    return packets;
}

#endif // SENDER_UTILITY_HPP