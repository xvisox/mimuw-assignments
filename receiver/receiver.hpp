#ifndef SIKRADIO_RECEIVER_HPP
#define SIKRADIO_RECEIVER_HPP

#include <thread>
#include "receiver_utility.hpp"
#include "receiver_params.hpp"
#include "../utils/audio_packet.h"
#include "../utils/const.h"
#include "../utils/types.h"
#include "buffer.hpp"

class Receiver {
private:
    ReceiverParameters params;
    byte_t buffer[BSIZE];       // The buffer will store raw data.
    Buffer packets_buffer;      // The buffer will store the packets to be printed.
    struct AudioPacket *packet; // The packet will store the data from the buffer.
    struct sockaddr_in client_address;
    int socket_fd;

    void init_packet(size_t packet_size) {
        // Allocate memory for the audio data.
        packet = static_cast<AudioPacket *>(calloc(packet_size, sizeof(byte_t)));
        if (packet == nullptr) fatal("Cannot allocate memory for the audio data");
    }

public:
    explicit Receiver(ReceiverParameters &params) : params(params), buffer(), packets_buffer(params.buffer_size),
                                                    packet(nullptr), client_address(), socket_fd(-1) {}

    ~Receiver() {
        free(packet);
        if (socket_fd > 0) CHECK_ERRNO(close(socket_fd));
    }

    void run() {
        std::thread receiver_thread(&Receiver::receiver, this);
        receiver_thread.detach();
        writer();
    }

    void receiver() {
        socket_fd = bind_socket(params.data_port);

        size_t empty_packet_size = sizeof(struct AudioPacket);
        size_t read_length;
        init_packet(empty_packet_size);
        do {
            read_length = read_message(socket_fd, &client_address, buffer, BSIZE);
            // Copy the data from the buffer to the packet.
            memcpy(packet, buffer, empty_packet_size);
            packet->first_byte_num = be64toh(packet->first_byte_num);
            packet->session_id = be64toh(packet->session_id);

            // Convert the data to a vector.
            byte_vector_t packet_data(buffer + empty_packet_size, buffer + read_length);
            std::optional<byte_vector_t> packet_data_opt = std::make_optional(std::move(packet_data));

            // Add the packet to the buffer.
            packets_buffer.add_packet(packet_data_opt,
                                      read_length - empty_packet_size,
                                      packet->first_byte_num, packet->session_id);
        } while (read_length > 0);
    }

    [[noreturn]] void writer() {
        while (true) {
            // Get the packet from the buffer.
            auto optional_packet = packets_buffer.read();
            if (!optional_packet.has_value()) continue;

            // Print the packet.
            auto data = optional_packet.value();
            fwrite(data.data(), sizeof(byte_t), data.size(), stdout);
        }
    }
};

#endif // SIKRADIO_RECEIVER_HPP