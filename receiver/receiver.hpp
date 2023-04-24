#ifndef SIKRADIO_RECEIVER_HPP
#define SIKRADIO_RECEIVER_HPP

#include <thread>
#include "receiver_utility.hpp"
#include "receiver_params.hpp"
#include "../utils/const.h"
#include "../utils/types.h"
#include "buffer.hpp"

class Receiver {
private:
    ReceiverParameters params;
    byte_t buffer[BSIZE];       // The buffer will store raw data.
    Buffer packets_buffer;      // The buffer will store the packets to be printed.
    struct sockaddr_in client_address;
    struct sockaddr_in sender_address;
    int socket_fd;

public:
    explicit Receiver(ReceiverParameters &params) : params(params), buffer(), packets_buffer(params.buffer_size),
                                                    client_address(), sender_address(), socket_fd(-1) {}

    ~Receiver() {
        if (socket_fd > 0) CHECK_ERRNO(close(socket_fd));
    }

    void run() {
        std::thread receiver_thread(&Receiver::receiver, this);
        receiver_thread.detach();
        writer();
    }

    void receiver() {
        sender_address = get_address(params.sender_addr.c_str(), params.data_port);
        socket_fd = bind_socket(params.data_port);

        packet_size_t empty_packet_size = sizeof(session_id_t) + sizeof(packet_id_t);
        session_id_t session_id;
        packet_id_t packet_id;
        size_t read_length;
        do {
            read_length = read_message(socket_fd, buffer, BSIZE, &client_address, &sender_address);
            // Convert the data from the buffer to the packet data.
            memcpy(&session_id, buffer, sizeof(session_id_t));
            memcpy(&packet_id, buffer + sizeof(session_id_t), sizeof(packet_id_t));

            // Convert the audio data to a vector of bytes.
            byte_vector_t packet_data(buffer + empty_packet_size, buffer + read_length);
            std::optional<byte_vector_t> packet_data_opt = std::make_optional(std::move(packet_data));

            // Add the packet to the buffer.
            packets_buffer.add_packet(packet_data_opt,
                                      read_length - empty_packet_size,
                                      be64toh(packet_id), be64toh(session_id));
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