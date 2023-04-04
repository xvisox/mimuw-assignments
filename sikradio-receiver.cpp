#include <iostream>
#include "receiver/session.hpp"
#include "receiver/receiver_params.hpp"
#include "receiver/receiver_utility.hpp"
#include "receiver/buffer.hpp"
#include "utils/audio_packet.h"

// The buffer will store raw data.
byte_t buffer[BSIZE];
// The packet will store the received data.
struct AudioPacket *packet = nullptr;
int socket_fd = -1;

void init_packet(size_t packet_size) {
    // Allocate memory for the audio data, but firstly free the old one.
    free(packet);
    packet = static_cast<AudioPacket *>(calloc(packet_size, sizeof(byte_t)));
    if (packet == nullptr) fatal("Cannot allocate memory for the audio data");
    memcpy(packet, buffer, packet_size);
}

void clean() {
    free(packet);
    CHECK_ERRNO(close(socket_fd));
}

int main(int argc, const char **argv) {
    atexit(clean);
    ReceiverParameters params = parse(argc, argv);
    port_t port = params.data_port;
    socket_fd = bind_socket(port);

    memset(buffer, 0, BSIZE);
    Session session;
    Buffer packets_buffer;
    struct sockaddr_in client_address{};
    size_t read_length;
    do {
        read_length = read_message(socket_fd, &client_address, buffer, BSIZE);
        init_packet(read_length);
        // FIXME: Remove this, only for debugging purposes.
        std::cout << "Received packet: " << packet->session_id << " " << packet->first_byte_num << std::endl;
        std::cout << "Data: " << packet->audio_data << std::endl;

        // Initialize the session.
        session.setup_if_not_initialized(packet, read_length);

    } while (read_length > 0);

    return 0;
}
