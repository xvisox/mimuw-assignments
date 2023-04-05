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
        // Set the session ID.
        packet->session_id = time(nullptr);
    }

public:
    explicit Sender(SenderParameters &params) : params(params), packet(nullptr), socket_fd(-1), address() {}

    ~Sender() {
        free(packet);
        CHECK_ERRNO(close(socket_fd));
    }

    void run() {
        // Get the address of the receiver and create a socket.
        address = get_send_address(params.dest_addr.c_str(), params.data_port);
        socket_fd = open_socket();

        // Send the audio data.
        packet_size_t psize = params.psize;
        size_t packet_size = sizeof(struct AudioPacket) + psize;
        init_packet(packet_size);
        while (!feof(stdin)) {
            // Read the audio data.
            size_t read_bytes = fread(packet->audio_data, sizeof(byte_t), psize, stdin);
            if (read_bytes < psize) {
                break;
            }
            // Set the first byte number.
            send_packet(&address, socket_fd, packet, packet_size);
            ENSURE(psize == read_bytes);
            packet->first_byte_num += psize;
        }
    }
};

#endif // SIKRADIO_SENDER_HPP