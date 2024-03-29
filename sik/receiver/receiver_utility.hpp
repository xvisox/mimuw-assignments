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
#include <boost/algorithm/string.hpp>
#include "../utils/err.h"
#include "../utils/const.h"
#include "../utils/types.h"
#include "../utils/common.h"
#include "station.hpp"

inline static void drop_membership(socket_t *socket_fd, struct ip_mreq *mreq) {
    if (*socket_fd < 0) return;
    if (setsockopt(*socket_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, mreq, sizeof(*mreq)))
        PRINT_ERRNO();

    CHECK_ERRNO(close(*socket_fd));
    *socket_fd = -1;
}

inline static void create_membership(struct pollfd *pfd, const char *mcast_addr, port_t port, struct ip_mreq *mreq) {
    int socket_fd = open_listener_socket();

    mreq->imr_interface.s_addr = htonl(INADDR_ANY);
    if (!inet_aton(mcast_addr, (struct in_addr *) &mreq->imr_multiaddr.s_addr))
        PRINT_ERRNO();

    if (setsockopt(socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, mreq, sizeof(*mreq)))
        PRINT_ERRNO();

    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);
    bind_socket(socket_fd, &address);

    pfd->fd = socket_fd;
    pfd->events = POLLIN;
    pfd->revents = 0;
}

inline static std::optional<Station> get_station(const std::string &reply,
                                                 struct sockaddr_in sender_address, socklen_t sender_address_len) {
    std::vector<std::string> parsable;
    boost::split(parsable, reply, boost::is_any_of(" "));
    if (parsable.size() < 4) {
        syslog("get_station: Invalid message type.");
        return std::nullopt;
    }

    // Validate multicast address.
    struct in_addr address{};
    if (inet_pton(AF_INET, parsable[1].c_str(), &address) != 1 || !IN_MULTICAST(ntohl(address.s_addr))) {
        syslog("get_station: Invalid multicast address.");
        return std::nullopt;
    }

    // Validate control port.
    int control_port;
    try {
        control_port = std::stoi(parsable[2]);
    } catch (...) {
        control_port = -1;
    }
    if (control_port < 1024 || control_port > UINT16_MAX) {
        syslog("get_station: Invalid control port.");
        return std::nullopt;
    }

    // Validate station name.
    std::string name;
    for (size_t i = 3; i != parsable.size(); ++i) name += parsable[i];
    if (name.empty() || name.size() > 64) {
        syslog("get_station: Invalid name.");
        return std::nullopt;
    }
    for (char c: name) {
        if (c < 32 || c > 127) {
            syslog("get_station: Invalid ASCII character in name.");
            return std::nullopt;
        }
    }

    Station station(parsable[1], name, static_cast<port_t>(control_port));
    station.address_length = sender_address_len;
    station.address = sender_address;
    return station;
}

inline static std::string get_request_str(missed_ids_t &missed_ids, std::string &prefix) {
    std::string request_str = prefix;
    size_t i = 0, size = missed_ids.size();
    for (auto &id: missed_ids) {
        request_str += std::to_string(id);
        if (++i == size) break;
        request_str += ",";
    }
    return (request_str + '\n');
}

inline static socket_t open_tcp_listener_socket(port_t port) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        PRINT_ERRNO();
    }

    int optval = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
        PRINT_ERRNO();

    struct sockaddr_in address = get_listener_address(port);
    bind_socket(socket_fd, &address);

    if (listen(socket_fd, QUEUE_LEN) < 0)
        PRINT_ERRNO();

    return socket_fd;
}

inline static bool send_init_message(socket_t client_fd, unsigned char msg[], ssize_t init_msg_len) {
    ssize_t len = write(client_fd, msg, init_msg_len);
    return (len == init_msg_len);
}

inline static bool clear_terminal(socket_t client_fd) {
    static const std::string clear_message = "\033[2J\033[0;0H";
    return write(client_fd, clear_message.c_str(), clear_message.size()) >= 0;
}

inline static std::string get_menu(std::set<Station> &stations, size_t picked_index) {
    std::string data;
    data.append("------------------------------------------------------------------------\r\n");
    data.append(" SIK Radio\r\n");
    data.append("------------------------------------------------------------------------\r\n\r\n");
    size_t i = 0;
    for (auto &station: stations) {
        if (picked_index == i) {
            data.append(" > ");
        }
        data.append(station.name);
        data.append("\r\n\r\n");
        i++;
    }
    data.append("------------------------------------------------------------------------");
    return data;
}

inline static bool send_menu(socket_t client_fd, std::string &menu) {
    return clear_terminal(client_fd) && write(client_fd, menu.c_str(), menu.size()) >= 0;
}

inline static bool isUp(size_t length, const char buffer[]) {
    // UP arrow
    return length == 3 && buffer[0] == 27 && buffer[1] == 91 && buffer[2] == 65;
}

inline static bool isDown(size_t length, const char buffer[]) {
    // DOWN arrow
    return length == 3 && buffer[0] == 27 && buffer[1] == 91 && buffer[2] == 66;
}

inline static bool isQuit(size_t length, const char buffer[]) {
    // CTRL + C
    return length == 1 && buffer[0] == 3;
}

#endif // RECEIVER_UTILITY_HPP
