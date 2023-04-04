#include <ctime>
#include <iostream>

#include "sender/sender_utility.hpp"
#include "sender/sender_params.hpp"

struct AudioPacket *packet = nullptr;
int socket_fd = -1;

void init_packet(size_t packet_size) {
    // Allocate memory for the audio data.
    packet = static_cast<AudioPacket *>(calloc(packet_size, sizeof(byte_t)));
    if (packet == nullptr) fatal("Cannot allocate memory for the audio data");
    // Set the session ID.
    packet->session_id = time(nullptr);
}

void clean() {
    free(packet);
    CHECK_ERRNO(close(socket_fd));
}

int main(int argc, const char **argv) {
    atexit(clean);
    SenderParameters params = parse(argc, argv);

    // FIXME: Remove this, only for debugging purposes.
    std::cout << params.dest_addr << std::endl;
    std::cout << params.data_port << std::endl;
    std::cout << params.psize << std::endl;
    std::cout << params.name << std::endl;

    // Get the address of the receiver and create a socket.
    struct sockaddr_in address = get_send_address(params.dest_addr.c_str(), params.data_port);
    socket_fd = open_socket();

    // Send the audio data.
    packet_size_t psize = params.psize;
    size_t packet_size = sizeof(struct AudioPacket) + psize;
    init_packet(packet_size);
    while (!feof(stdin)) {
        // Read the audio data.
        size_t read_bytes = fread(packet->audio_data, sizeof(char), psize, stdin);
        if (read_bytes < psize) {
            break;
        }
        // Set the first byte number.
        send_packet(&address, socket_fd, packet, packet_size);
        ENSURE(psize == read_bytes);
        packet->first_byte_num += psize;
    }

    return 0;
}
