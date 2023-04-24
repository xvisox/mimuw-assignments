#ifndef SIKRADIO_SENDER_HPP
#define SIKRADIO_SENDER_HPP

#include <netinet/in.h>

#include <utility>
#include "sender_params.hpp"

class Sender {
private:
    SenderParameters params;
    struct sockaddr_in address;
    int socket_fd;

public:
    explicit Sender(SenderParameters &params) : params(params), address(), socket_fd(-1) {}

    ~Sender() {
        if (socket_fd > 0) CHECK_ERRNO(close(socket_fd));
    }

    void run() {
        // Get the address of the receiver and create a socket.
        address = get_address(params.dest_addr.c_str(), params.data_port);
        socket_fd = open_socket();
        connect_socket(socket_fd, &address);

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
            if (read_bytes < params.psize) break;

            // Send the audio data.
            send_packet(socket_fd, packet.data(), packet_size);
            // Update the packet.
            byte_num += params.psize;
            packet_id_t aux = htobe64(byte_num);
            memcpy(packet.data() + sizeof(session_id_t), &aux, sizeof(packet_id_t));
        }
    }
};

#endif // SIKRADIO_SENDER_HPP