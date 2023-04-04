#include <iostream>
#include "receiver/receiver_params.hpp"
#include "receiver/receiver_utility.hpp"

#define BUFFER_SIZE (1<<16)

char shared_buffer[BUFFER_SIZE];

int main(int argc, const char **argv) {
    ReceiverParameters params = parse(argc, argv);
    port_t port = params.data_port;
    std::cout << "Listening on port " << port << std::endl;

    memset(shared_buffer, 0, sizeof(shared_buffer));
    int socket_fd = bind_socket(port);

    struct sockaddr_in client_address{};
    size_t read_length;
    size_t bound = INT32_MAX;
    do {
        read_length = read_message(socket_fd, &client_address, shared_buffer, sizeof(shared_buffer));
        char *client_ip = inet_ntoa(client_address.sin_addr);
        uint16_t client_port = ntohs(client_address.sin_port);
        printf("received %zd bytes from client %s:%u\n", read_length, client_ip, client_port);
        shared_buffer[read_length] = '\n';
    } while (read_length > 0 && (--bound));

    CHECK_ERRNO(close(socket_fd));

    return 0;
}
