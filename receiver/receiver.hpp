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
    using stations_t = std::vector<Station>;

    ReceiverParameters params;
    byte_t buffer[BSIZE];       // The buffer will store raw data.
    Buffer packets_buffer;      // The buffer will store the packets to be printed.
    struct sockaddr_in discovery_address;
    size_t discovery_address_len;
    socket_t discovery_socket_fd;
    struct pollfd fds[2];
    stations_t stations;
    struct ip_mreq mreq;
    Station *picked_station;

    void remove_expired_stations_and_pick() {
        auto it = stations.begin();
        while (it != stations.end()) {
            if (it->is_expired()) {
                if (picked_station == &(*it)) {
                    picked_station = nullptr;
                    drop_membership(&fds[1].fd, &mreq);
                }
                // Remove the station from the list.
                syslog("Station: %s expired", it->name.c_str());
                it = stations.erase(it);
            } else {
                ++it;
            }
        }
        pick_best_station();
    }

    void update_stations(std::optional<Station> station_opt) {
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
        remove_expired_stations_and_pick();
    }

    void pick_best_station() {
        if (stations.empty()) return;
        // If the picked station is our favourite, do not change it.
        if (picked_station != nullptr && picked_station->has_name(params.name)) return;

        for (auto &station: stations) {
            if (station.has_name(params.name)) {
                drop_membership(&fds[1].fd, &mreq);
                create_membership(&fds[1], station.mcast_addr.c_str(), station.data_port, &mreq);
                picked_station = &station;
                packets_buffer.clear();
                syslog("Picked favourite station: %s", station.name.c_str());
                return;
            }
        }

        if (fds[1].fd > 0) return;
        // If there is no station with the given name, pick the first one.
        create_membership(&fds[1], stations[0].mcast_addr.c_str(), stations[0].data_port, &mreq);
        picked_station = &stations[0];
        packets_buffer.clear();
        syslog("Picked first station: %s", stations[0].name.c_str());
    }

public:
    explicit Receiver(ReceiverParameters &params) : params(params), buffer(), packets_buffer(params.buffer_size),
                                                    discovery_address(), discovery_address_len(0),
                                                    discovery_socket_fd(-1), fds(), stations(),
                                                    mreq(), picked_station(nullptr) {
        // Initialize socket for sending control packets.
        discovery_address = get_remote_address(params.discover_addr.c_str(), params.control_port, false);
        discovery_address_len = sizeof(discovery_address);
        discovery_socket_fd = open_multicast_socket();
        // Initialize poll structure.
        // Discovery socket.
        fds[0].fd = discovery_socket_fd;
        fds[0].events = POLLIN;
        // Radio socket.
        fds[1].fd = -1;
    }

    ~Receiver() {
        if (discovery_socket_fd > 0) CHECK_ERRNO(close(discovery_socket_fd));
        if (fds[1].fd > 0) CHECK_ERRNO(close(fds[1].fd));
    }

    void run() {
        std::thread receiver_thread(&Receiver::listening_controller, this);
        std::thread discovery_thread(&Receiver::discovery_controller, this);
        std::thread requests_thread(&Receiver::requests_controller, this);
        receiver_thread.detach();
        discovery_thread.detach();
        requests_thread.detach();
        writer();
    }

    [[noreturn]] void listening_controller() {
        packet_size_t empty_packet_size = sizeof(session_id_t) + sizeof(packet_id_t);
        session_id_t session_id;
        packet_id_t packet_id;

        while (true) {
            int res = poll(fds, 2, LOOKUP_TIME_MS);
            if (res < 0) PRINT_ERRNO();
            if (res == 0) remove_expired_stations_and_pick();

            if (fds[0].revents & POLLIN) {
                ssize_t len = recv(discovery_socket_fd, buffer, BSIZE, NO_FLAGS);
                if (len < 0) continue;

                buffer[len] = '\0';
                syslog("Discovered station %s", buffer);
                // Parse message to station info.
                auto station_opt = get_station(buffer);
                if (!station_opt.has_value()) continue;

                update_stations(station_opt);
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

    [[noreturn]] void discovery_controller() {
        const auto lookup_msg_len = strlen(LOOKUP);
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(LOOKUP_TIME_MS));
            sendto(discovery_socket_fd, LOOKUP, lookup_msg_len, NO_FLAGS,
                   (struct sockaddr *) &discovery_address, discovery_address_len);
        }
    }

    [[noreturn]] void requests_controller() {
        std::string request_msg_prefix = std::string(REXMIT) + " ";
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(params.rtime));
            auto missed_ids = packets_buffer.get_missed_ids();
            if (missed_ids.empty()) continue;

            // Send request for missed packets.
            auto request_msg = get_request_str(missed_ids, request_msg_prefix);
            sendto(discovery_socket_fd, request_msg.c_str(), request_msg.size(), NO_FLAGS,
                   (struct sockaddr *) &discovery_address, discovery_address_len);
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