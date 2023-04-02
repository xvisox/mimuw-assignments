#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "err.h"
#include "sender_utility.h"

#define STUDENT_NUM 438596
#define DEFAULT_NAME "Nienazwany Nadajnik"

// Set the default values.
uint16_t DATA_PORT = 20000 + (STUDENT_NUM % 10000);
uint64_t PSIZE = (1 << 9);
char *DEST_ADDR = NULL;
char *NAME = DEFAULT_NAME;
struct AudioPacket *packet = NULL;

void parse_args(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "a:P:p:n:")) != -1) {
        switch (opt) {
            case 'a':
                // Set the receiver's IP address.
                DEST_ADDR = optarg;
                break;
            case 'P':
                // Set the receiver's port.
                DATA_PORT = read_port(optarg);
                break;
            case 'p':
                // Set the packet size.
                PSIZE = read_size(optarg);
                break;
            case 'n':
                // Set the name of the sender.
                NAME = optarg;
                break;
            case '?':
                // Unknown option.
                fatal("Unknown option: %c", optopt);
            default:
                fatal("getopt() returned an unexpected value: %d", opt);
        }
    }
}

void init_packet() {
    // Allocate memory for the audio data.
    packet = calloc(sizeof(struct AudioPacket) + PSIZE, sizeof(char));
    // Set the session ID.
    packet->session_id = time(NULL);
}

void clean_packet() {
    free(packet);
}

int main(int argc, char **argv) {
    atexit(clean_packet);
    parse_args(argc, argv);
    // Check if the required options were set.
    if (DEST_ADDR == NULL) {
        fatal("The receiver's IP address must be set");
    }

    // Get the address of the receiver.
    struct sockaddr_in send_address = get_send_address(DEST_ADDR, DATA_PORT);
    // Create a socket.
    int socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        PRINT_ERRNO();
    }

    // Print the configuration.
    printf("Receiver's IP address: %s, port: %u, packet size: %lu, name: %s \n", DEST_ADDR, DATA_PORT, PSIZE, NAME);

    // Send the audio data.
    init_packet();
    size_t packet_size = sizeof(struct AudioPacket) + PSIZE;
    while (!feof(stdin)) {
        // Read the audio data.
        size_t read_bytes = fread(packet->audio_data, sizeof(char), PSIZE, stdin);
        if (read_bytes < PSIZE) {
            break;
        }
        // Set the first byte number.
        send_packet(&send_address, socket_fd, packet, packet_size);
        ENSURE(PSIZE == read_bytes);
        packet->first_byte_num += PSIZE;
    }

    return 0;
}
