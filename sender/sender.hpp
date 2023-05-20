#ifndef SIKRADIO_SENDER_HPP
#define SIKRADIO_SENDER_HPP

#include <netinet/in.h>

#include <utility>
#include <thread>
#include "sender_params.hpp"
#include "../utils/common.h"
#include "cache.hpp"

class Sender {
private:
    struct sockaddr_in remote_address;
    struct sockaddr_in receiver_address;
    struct sockaddr_in listener_address;
    socket_t multicast_socket_fd;
    socket_t listener_socket_fd;
    SenderParameters params;
    PacketsCache cache;
    MissedPackets missed;
    byte_t buffer[CTRL_BUF_SIZE + 1];

    std::string get_reply_str() const {
        std::string reply = std::string(REPLY) + " ";
        reply += params.mcast_addr + " ";
        reply += std::to_string(params.data_port) + " ";
        reply += params.name;
        return reply;
    }

public:
    explicit Sender(SenderParameters &params) : remote_address(), receiver_address(), listener_address(),
                                                multicast_socket_fd(-1), listener_socket_fd(-1), params(params),
                                                cache((params.fsize / params.psize) * params.psize),
                                                missed(), buffer() {
        // Initialize socket for sending packets.
        remote_address = get_remote_address(params.mcast_addr.c_str(), params.data_port, true);
        multicast_socket_fd = open_multicast_socket();
        connect_socket(multicast_socket_fd, &remote_address);
        // Initialize socket for receiving control packets.
        listener_address = get_listener_address(params.control_port);
        listener_socket_fd = open_listener_socket();
        bind_socket(listener_socket_fd, &listener_address);
    }

    ~Sender() {
        if (multicast_socket_fd > 0) CHECK_ERRNO(close(multicast_socket_fd));
        if (listener_socket_fd > 0) CHECK_ERRNO(close(listener_socket_fd));
    }

    void run() {
        std::thread controller_thread(&Sender::controller, this);
        std::thread retransmission_thread(&Sender::retransmitter, this);
        controller_thread.detach();
        retransmission_thread.detach();
        sender();
    }

    void sender() {
        // Initialize the packet.
        packet_size_t empty_packet_size = sizeof(session_id_t) + sizeof(packet_id_t);
        packet_size_t packet_size = empty_packet_size + params.psize;
        byte_vector_t packet(packet_size);
        // Prepare the packet.
        session_id_t session_id = htobe64(time(nullptr));
        packet_id_t byte_num = 0;
        memcpy(packet.data(), &session_id, sizeof(session_id_t));
        memcpy(packet.data() + sizeof(session_id_t), &byte_num, sizeof(packet_id_t));
        while (!feof(stdin)) {
            // Read the audio data.
            size_t read_bytes = fread(packet.data() + empty_packet_size, sizeof(byte_t), params.psize, stdin);
            if (read_bytes < (size_t) params.psize) break;

            // Send the audio data.
            send_packet(multicast_socket_fd, packet.data(), packet_size);
            // (!!!) Cached packet is already in the network byte order but byte_num isn't.
            cache.push(byte_num, packet);
            // Update the packet.
            byte_num += params.psize;
            packet_id_t aux = htobe64(byte_num);
            memcpy(packet.data() + sizeof(session_id_t), &aux, sizeof(packet_id_t));
        }
    }

    [[noreturn]] void controller() {
        auto address_length = (socklen_t) sizeof(receiver_address);
        const auto lookup_msg_len = strlen(LOOKUP);
        const auto rexmit_msg_len = strlen(REXMIT);
        const auto reply = get_reply_str();

        while (true) {
            ssize_t received_bytes = recvfrom(listener_socket_fd, buffer, CTRL_BUF_SIZE, NO_FLAGS,
                                              (struct sockaddr *) &receiver_address, &address_length);
            if (received_bytes < 0) continue;

            if (!strncmp(buffer, LOOKUP, lookup_msg_len)) {
                send_reply(listener_socket_fd, reply, &receiver_address, address_length);
            }

            if (!strncmp(buffer, REXMIT, rexmit_msg_len)) {
                std::vector<packet_id_t> missed_packets = parse_rexmit(buffer, received_bytes);
                missed.push_all(missed_packets);
            }
        }
    }

    [[noreturn]] void retransmitter() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(params.rtime));
            std::vector<packet_id_t> missed_packets = missed.pop_all();
            for (packet_id_t missed_packet: missed_packets) {
                try {
                    byte_vector_t packet = cache.pop(missed_packet);
                    send_packet(multicast_socket_fd, packet.data(), packet.size());
                } catch (std::out_of_range &e) {
                    continue;
                }
            }
        }
    }
};

#endif // SIKRADIO_SENDER_HPP