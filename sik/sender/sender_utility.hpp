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

/*
 * Autor: Paweł Parys
 * Błąd w send można zignorować (najlepiej pisząc w komentarzu, że ignorujemy)
 */
inline static void send_packet(socket_t socket_fd, byte_t *packet, packet_size_t packet_size) {
    send(socket_fd, packet, packet_size, NO_FLAGS);
}

inline static void send_reply(socket_t socket_fd, const std::string &reply,
                              struct sockaddr_in *receiver_address, socklen_t address_length) {
    sendto(socket_fd, reply.c_str(), reply.size(), NO_FLAGS,
           (struct sockaddr *) receiver_address, address_length);
}

inline static std::vector<packet_id_t> parse_rexmit(byte_t *buffer) {
    std::string str(reinterpret_cast<char *>(buffer));
    std::vector<std::string> parsable;
    boost::split(parsable, str, boost::is_any_of(", "));

    std::vector<packet_id_t> packets;
    for (auto it = std::next(parsable.begin()); it != parsable.end(); it++) {
        packet_id_t missed_id;
        try {
            missed_id = stoll(*it);
        } catch (...) {
            syslog("parse_rexmit: Invalid retransmission request.");
            packets.clear();
            return packets;
        }
        packets.push_back(missed_id);
    }
    return packets;
}

#endif // SENDER_UTILITY_HPP