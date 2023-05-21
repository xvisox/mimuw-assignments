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
    using stations_t = std::set<Station>;

    ReceiverParameters params;
    byte_t buffer[BSIZE];       // The buffer will store raw data.
    Buffer packets_buffer;      // The buffer will store the packets to be printed.
    struct sockaddr_in discovery_address;
    size_t discovery_address_len;
    socket_t discovery_socket_fd;
    struct pollfd radio_fds[2];
    struct pollfd ui_fds[1 + MAX_CONNECTIONS];
    byte_t ui_buffer[UI_BUF_SIZE];
    stations_t stations;
    struct ip_mreq mreq;
    std::set<Station>::iterator picked_station;
    std::mutex stations_mutex;
    size_t picked_index;

    bool pick_favourite_station() {
        int i = 0;
        for (auto station = stations.begin(); station != stations.end(); station++) {
            if (station->has_name(params.name)) {
                drop_membership(&radio_fds[1].fd, &mreq);
                create_membership(&radio_fds[1], station->mcast_addr.c_str(), station->data_port, &mreq);
                picked_station = station;
                picked_index = i;
                packets_buffer.clear();
                syslog("Picked favourite station: %s", station->name.c_str());
                return true;
            }
            i++;
        }
        return false;
    }

    void pick_first_station() {
        if (stations.empty()) return;

        auto station = stations.begin();
        create_membership(&radio_fds[1], station->mcast_addr.c_str(), station->data_port, &mreq);
        picked_station = stations.begin();
        picked_index = 0;
        packets_buffer.clear();
        syslog("Picked first station: %s", station->name.c_str());
    }

    void pick_best_station() {
        if (!pick_favourite_station()) pick_first_station();
    }

    void pick_station(size_t index) {
        if (picked_index == index) return;

        auto station = stations.begin();
        std::advance(station, index);
        drop_membership(&radio_fds[1].fd, &mreq);
        create_membership(&radio_fds[1], station->mcast_addr.c_str(), station->data_port, &mreq);
        picked_station = station;
        picked_index = index;
        packets_buffer.clear();
        syslog("Picked station: %s", station->name.c_str());
    }

    size_t get_new_index() {
        if (picked_station == stations.end()) return 0;

        auto station = stations.begin();
        size_t index = 0;
        while (station != stations.end()) {
            if (station == picked_station) return index;
            station++;
            index++;
        }
        return 0;
    }

    void remove_expired_stations_and_pick() {
        std::lock_guard<std::mutex> lock(stations_mutex);
        bool picked_expired = false;
        size_t initial_size = stations.size();
        auto it = stations.begin();
        while (it != stations.end()) {
            if (it->is_expired()) {
                if (picked_station == it) {
                    picked_station = stations.end();
                    picked_expired = true;
                    drop_membership(&radio_fds[1].fd, &mreq);
                }
                // Remove the station from the list.
                syslog("Station: %s expired", it->name.c_str());
                it = stations.erase(it);
            } else {
                ++it;
            }
        }
        // Nothing changed.
        if (initial_size == stations.size()) return;

        if (picked_expired) {
            pick_best_station();
        } else if (!stations.empty()) {
            picked_index = get_new_index();
        }
        notify_all();
    }

    void update_stations_and_pick(std::optional<Station> station_opt) {
        std::lock_guard<std::mutex> lock(stations_mutex);
        auto station = station_opt.value();
        stations.insert(station);
        // If the station is not in the list, add it.
        if (picked_station == stations.end())
            pick_first_station();
        else if (station.has_name(params.name)) {
            pick_favourite_station();
        } else {
            picked_index = get_new_index();
        }
        notify_all();
    }

    void notify_all() {
        std::string menu = get_menu(stations, picked_index);
        for (int i = 1; i < 1 + MAX_CONNECTIONS; i++) {
            if (ui_fds[i].fd > 0) {
                send_menu(ui_fds[i].fd, menu);
            }
        }
    }

public:
    explicit Receiver(ReceiverParameters &params) : params(params), buffer(), packets_buffer(params.buffer_size),
                                                    discovery_address(), discovery_address_len(0),
                                                    discovery_socket_fd(-1), radio_fds(), ui_fds(), ui_buffer(),
                                                    stations(),
                                                    mreq(), picked_station(stations.end()), stations_mutex(),
                                                    picked_index(0) {
        // Initialize socket for sending control packets.
        discovery_address = get_remote_address(params.discover_addr.c_str(), params.control_port, false);
        discovery_address_len = sizeof(discovery_address);
        discovery_socket_fd = open_multicast_socket();
        // Initialize poll structure.
        // Discovery socket.
        radio_fds[0].fd = discovery_socket_fd;
        radio_fds[0].events = POLLIN;
        // Radio socket.
        radio_fds[1].fd = -1;
        // UI socket.
        ui_fds[0].fd = open_tcp_listener_socket(params.ui_port);
        ui_fds[0].events = POLLIN;
        // Initialize to all fds to -1.
        for (int i = 1; i < 1 + MAX_CONNECTIONS; ++i) {
            ui_fds[i].fd = -1;
        }
    }

    ~Receiver() {
        if (radio_fds[0].fd > 0) CHECK_ERRNO(close(radio_fds[0].fd > 0));
        if (radio_fds[1].fd > 0) CHECK_ERRNO(close(radio_fds[1].fd));
        if (ui_fds[0].fd > 0) CHECK_ERRNO(close(ui_fds[0].fd));
    }

    void run() {
        std::thread receiver_thread(&Receiver::listening_controller, this);
        std::thread discovery_thread(&Receiver::discovery_controller, this);
        std::thread requests_thread(&Receiver::requests_controller, this);
        std::thread interface_thread(&Receiver::ui_controller, this);
        receiver_thread.detach();
        discovery_thread.detach();
        requests_thread.detach();
        interface_thread.detach();
        writer();
    }

    [[noreturn]] void listening_controller() {
        packet_size_t empty_packet_size = sizeof(session_id_t) + sizeof(packet_id_t);
        session_id_t session_id;
        packet_id_t packet_id;

        while (true) {
            int res = poll(radio_fds, 2, LOOKUP_TIME_MS);
            if (res < 0) PRINT_ERRNO();
            remove_expired_stations_and_pick();

            if (radio_fds[0].revents & POLLIN) {
                ssize_t len = recv(discovery_socket_fd, buffer, BSIZE, NO_FLAGS);
                if (len < 0) continue;

                buffer[len] = '\0';
                syslog("Discovered station %s", buffer);
                // Parse message to station info.
                auto station_opt = get_station(buffer);
                if (station_opt.has_value()) update_stations_and_pick(station_opt);
            }

            if (radio_fds[1].revents & POLLIN) {
                size_t read_length = read_message(radio_fds[1].fd, buffer, BSIZE, empty_packet_size);

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

    [[noreturn]] void ui_controller() {
        unsigned char IAC_WILL_ECHO[] = {255, 251, 1};
        unsigned char IAC_WILL_SUPPRESS_GO_AHEAD[] = {255, 251, 3};
        ssize_t init_msg_len = sizeof(IAC_WILL_ECHO) / sizeof(char);
        while (true) {
            int res = poll(ui_fds, 1 + MAX_CONNECTIONS, -1);
            if (res < 0) PRINT_ERRNO();

            // Accept new connections.
            if (ui_fds[0].revents & POLLIN) {
                int client_fd = accept(ui_fds[0].fd, nullptr, nullptr);
                if (client_fd < 0) continue;

                if (!send_init_message(client_fd, IAC_WILL_ECHO, init_msg_len) ||
                    !send_init_message(client_fd, IAC_WILL_SUPPRESS_GO_AHEAD, init_msg_len)) {
                    CHECK_ERRNO(close(client_fd));
                    continue;
                }

                // Add the client to the list.
                bool accepted = false;
                for (int i = 1; i < 1 + MAX_CONNECTIONS; ++i) {
                    if (ui_fds[i].fd == -1) {
                        ui_fds[i].fd = client_fd;
                        ui_fds[i].events = POLLIN;
                        {
                            std::lock_guard<std::mutex> lock(stations_mutex);
                            std::string menu = get_menu(stations, picked_index);
                            send_menu(client_fd, menu);
                            accepted = true;
                        }
                        break;
                    }
                }
                if (!accepted) CHECK_ERRNO(close(client_fd));
            }

            // Handle messages from clients.
            for (int i = 1; i < 1 + MAX_CONNECTIONS; ++i) {
                if (ui_fds[i].revents & POLLIN) {
                    size_t read_length = read(ui_fds[i].fd, ui_buffer, UI_BUF_SIZE - 1);
                    if (read_length == 0) {
                        syslog("Client disconnected");
                        CHECK_ERRNO(close(ui_fds[i].fd));
                        ui_fds[i].fd = -1;
                        continue;
                    }

                    // If there are no stations, ignore the message.
                    if (stations.empty()) continue;

                    std::lock_guard<std::mutex> lock(stations_mutex);
                    size_t index;
                    if (isUp(read_length, ui_buffer)) {
                        index = (picked_index + stations.size() - 1) % stations.size();
                    } else if (isDown(read_length, ui_buffer)) {
                        index = (picked_index + 1) % stations.size();
                    } else {
                        continue;
                    }
                    pick_station(index);
                    notify_all();
                }
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