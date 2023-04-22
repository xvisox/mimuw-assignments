#ifndef SIKRADIO_SENDER_HPP
#define SIKRADIO_SENDER_HPP

#include <netinet/in.h>

#include <utility>
#include "sender_params.hpp"

class Sender {
private:
    SenderParameters params;
    struct AudioPacket *packet;
    struct sockaddr_in address;
    int socket_fd;

    void init_packet(size_t packet_size) {
        // Allocate memory for the audio data.
        packet = static_cast<AudioPacket *>(calloc(packet_size, sizeof(byte_t)));
        if (packet == nullptr) fatal("Cannot allocate memory for the audio data");
    }

public:
    explicit Sender(SenderParameters &params) : params(params), packet(nullptr), address(), socket_fd(-1) {}


    ~Sender() {
        free(packet);
        if (socket_fd > 0) CHECK_ERRNO(close(socket_fd));
    }

    void run() {
        // Get the address of the receiver and create a socket.
        address = get_send_address(params.dest_addr.c_str(), params.data_port);
        socket_fd = open_socket();

        packet_size_t psize = params.psize;
        size_t packet_size = sizeof(struct AudioPacket) + psize;
        init_packet(packet_size);
        packet->session_id = htobe64(time(nullptr));
        packet_id_t byte_num = 0;
        while (!feof(stdin)) {
            // Read the audio data.
            size_t read_bytes = fread(packet->audio_data, sizeof(byte_t), psize, stdin);
            if (read_bytes < psize) break;

            // Send the audio data.
            send_packet(&address, socket_fd, packet, packet_size);
            // Update the packet.
            byte_num += psize;
            packet->first_byte_num = htobe64(byte_num);
        }
    }
};

#endif // SIKRADIO_SENDER_HPP