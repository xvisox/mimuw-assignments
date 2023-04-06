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
    int socket_fd;

    void init_packet(size_t packet_size) {
        // Allocate memory for the audio data, but firstly free the old one.
        free(packet);
        packet = static_cast<AudioPacket *>(calloc(packet_size, sizeof(byte_t)));
        if (packet == nullptr) fatal("Cannot allocate memory for the audio data");
        memcpy(packet, buffer, packet_size);
    }

public:
    explicit Receiver(ReceiverParameters &params) : params(params), packet(nullptr), socket_fd(-1),
                                                    packets_buffer(params.buffer_size), buffer{} {}

    ~Receiver() {
        free(packet);
        CHECK_ERRNO(close(socket_fd));
    }

    void run() {
        std::thread receiver_thread(&Receiver::receiver, this);
        writer(); // The writer thread will be the main thread.
        receiver_thread.join();
    }

    void receiver() {
        socket_fd = bind_socket(params.data_port);
        struct sockaddr_in client_address{};
        size_t read_length;
        do {
            read_length = read_message(socket_fd, &client_address, buffer, BSIZE);
            init_packet(read_length);
            // FIXME: Remove this, only for debugging purposes.
            std::cerr << "Received packet: " << packet->session_id << " " << packet->first_byte_num
                      << " Data: " << packet->audio_data << std::endl;

            // Add the packet to the buffer.
            packets_buffer.add_packet(packet, read_length);
        } while (read_length > 0);
    }

    void writer() {
        while (true) {
            // Get the packet from the buffer.
            try {
                auto data = packets_buffer.read();
                std::cout << "Raw data: " << std::string(data.begin(), data.end()) << std::endl;
            } catch (std::exception &e) {
                // Buffer is empty, wait for a while.
            }
        }
    }
};

#endif // SIKRADIO_RECEIVER_HPP