#ifndef SIKRADIO_SENDER_HPP
#define SIKRADIO_SENDER_HPP

#include <netinet/in.h>

#include <utility>
#include <thread>
#include "sender_params.hpp"
#include "packets_queue.hpp"

class Sender {
private:
    SenderParameters params;
    PacketsQueue packets_queue;
    struct AudioPacket *packet;
    struct sockaddr_in address;
    int socket_fd;

    void init_packet(size_t packet_size) {
        // Allocate memory for the audio data.
        packet = static_cast<AudioPacket *>(calloc(packet_size, sizeof(byte_t)));
        if (packet == nullptr) fatal("Cannot allocate memory for the audio data");
        // Set the session ID.
        packet->session_id = htobe64(time(nullptr));
    }

public:
    explicit Sender(SenderParameters &params) : params(params), packet(nullptr),
                                                socket_fd(-1), address() {}

    ~Sender() {
        free(packet);
        CHECK_ERRNO(close(socket_fd));
    }

    void reader(packet_size_t packet_size) {
        // Initialize the packet.
        init_packet(packet_size);

        // Read the audio data.
        packet_size_t psize = params.psize;
        packet_id_t byte_num = 0;
        while (!feof(stdin)) {
            size_t read_bytes = fread(packet->audio_data, sizeof(byte_t), psize, stdin);
            if (read_bytes < psize) {
                break;
            }
            // Update the packet.
            packet->first_byte_num = htobe64(byte_num);
            byte_num += psize;
            // Copy the packet into different pointer.
            auto *packet_copy = static_cast<AudioPacket *>(calloc(packet_size, sizeof(byte_t)));
            if (packet_copy == nullptr) fatal("Cannot allocate memory for the audio data");
            memcpy(packet_copy, packet, packet_size);
            // Push the packet to the queue.
            packets_queue.push(packet_copy);
        }
        // Null packet indicates the end of the stream.
        packets_queue.push(nullptr);
    }

    void sender(packet_size_t packet_size) {
        // Get the address of the receiver and create a socket.
        address = get_send_address(params.dest_addr.c_str(), params.data_port);
        socket_fd = open_socket();

        struct AudioPacket *audio_packet;
        // Send the audio data.
        while (true) {
            if (packets_queue.empty()) continue;

            // Get the next packet.
            audio_packet = packets_queue.pop();
            if (audio_packet == nullptr) break;
            send_packet(&address, socket_fd, audio_packet, packet_size);
            free(audio_packet);
        }
    }

    void run() {
        size_t packet_size = sizeof(struct AudioPacket) + params.psize;
        // Create a thread for reading the audio data.
        std::thread reader_thread(&Sender::reader, this, packet_size);
        sender(packet_size);
        reader_thread.join();
    }
};

#endif // SIKRADIO_SENDER_HPP