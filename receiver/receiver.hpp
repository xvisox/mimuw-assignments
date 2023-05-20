#ifndef SIKRADIO_RECEIVER_HPP
#define SIKRADIO_RECEIVER_HPP

#include <thread>
#include <sys/poll.h>
#include "receiver_utility.hpp"
#include "receiver_params.hpp"
#include "../utils/const.h"
#include "../utils/types.h"
#include "../utils/common.h"
#include "buffer.hpp"

class Receiver {
private:
    ReceiverParameters params;
    byte_t buffer[BSIZE];       // The buffer will store raw data.
    Buffer packets_buffer;      // The buffer will store the packets to be printed.
    struct sockaddr_in discovery_address;
    socket_t discovery_socket_fd;
    struct pollfd fds[2];
    std::vector<Station> stations;
    struct ip_mreq mreq;

public:
    explicit Receiver(ReceiverParameters &params) : params(params), buffer(), packets_buffer(params.buffer_size),
                                                    discovery_address(), discovery_socket_fd(-1), fds(), stations(),
                                                    mreq() {
        // Initialize socket for sending control packets.
        discovery_address = get_remote_address(params.discover_addr.c_str(), params.control_port, false);
        discovery_socket_fd = open_multicast_socket();
        // Initialize poll structure.
        // Discovery socket.
        fds[0].fd = discovery_socket_fd;
        fds[0].events = POLLIN;
        // Radio socket.
        fds[1].fd = -1;
        fds[1].events = POLLIN;
    }

    ~Receiver() {
        if (discovery_socket_fd > 0) CHECK_ERRNO(close(discovery_socket_fd));
        if (fds[1].fd > 0) CHECK_ERRNO(close(fds[1].fd));
    }

    void run() {
        std::thread receiver_thread(&Receiver::receiver, this);
        std::thread controller_thread(&Receiver::controller, this);
        receiver_thread.detach();
        controller_thread.detach();
        writer();
    }

    [[noreturn]] void receiver() {
        Station *picked_station;
        packet_size_t empty_packet_size = sizeof(session_id_t) + sizeof(packet_id_t);
        session_id_t session_id;
        packet_id_t packet_id;

        while (true) {
            int res = poll(fds, 2, NO_TIMEOUT);
            if (res < 0) PRINT_ERRNO();

            // Remove all stations that did not respond for a long time.
            auto it = stations.begin();
            while (it != stations.end()) {
                if (it->is_expired()) {
                    std::cerr << "receiver: Station " << it->name << " is old." << std::endl;
                    if (picked_station == &(*it)) {
                        picked_station = nullptr;
                        drop_membership(&fds[1].fd, &mreq);
                    }
                    it = stations.erase(it);
                } else {
                    ++it;
                }
            }

            if (fds[0].revents & POLLIN) {
                ssize_t len = recv(discovery_socket_fd, buffer, BSIZE, NO_FLAGS);
                if (len < 0) continue;

                // Parse message to station info.
                buffer[len] = '\0';
                auto station_opt = get_station(buffer);
                if (!station_opt.has_value()) continue;

                // If the station is already in the list, update it.
                bool found = false;
                auto station = station_opt.value();
                for (auto &s: stations) {
                    if (s == station) {
                        s.update_last_response();
                        found = true;
                        break;
                    }
                }
                // If the station is not in the list, add it.
                if (!found) stations.push_back(station);

                // If the station is the one we are looking for, open the radio socket.
                if (station.has_name(params.name)) {
                    drop_membership(&fds[1].fd, &mreq);
                    fds[1].fd = create_membership(station.mcast_addr.c_str(), station.data_port, &mreq);
                    fds[1].events = POLLIN;
                    fds[1].revents = 0;
                    picked_station = &station;
                } else if (!stations.empty() && fds[1].fd < 0) {
                    // Pick any if nothing is selected.
                    fds[1].fd = create_membership(stations[0].mcast_addr.c_str(), stations[0].data_port, &mreq);
                    fds[1].events = POLLIN;
                    fds[1].revents = 0;
                    picked_station = &stations[0];
                }
            }

            if (fds[1].revents & POLLIN) {
                size_t read_length = read_message(fds[1].fd, buffer, BSIZE, empty_packet_size);

                memcpy(&session_id, buffer, sizeof(session_id_t));
                memcpy(&packet_id, buffer + sizeof(session_id_t), sizeof(packet_id_t));

                // Convert the audio data to a vector of bytes.
                byte_vector_t packet_data(buffer + empty_packet_size, buffer + read_length);
                std::optional<byte_vector_t> packet_data_opt = std::make_optional(std::move(packet_data));

                // Add the packet to the buffer.
                packets_buffer.add_packet(packet_data_opt,
                                          read_length - empty_packet_size,
                                          be64toh(packet_id), be64toh(session_id));
            }
        }
    }

    [[noreturn]] void controller() {
        const auto lookup_msg_len = strlen(LOOKUP);
        const auto discovery_addr_len = sizeof(discovery_address);
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(LOOKUP_TIME_MS));
            sendto(discovery_socket_fd, LOOKUP, lookup_msg_len, NO_FLAGS,
                   (struct sockaddr *) &discovery_address, discovery_addr_len);
        }
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