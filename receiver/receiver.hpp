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
    using stations_iterator_t = stations_t::iterator;

    ReceiverParameters params;
    byte_t buffer[BSIZE];                       // The buffer will store raw data.
    Buffer packets_buffer;                      // The buffer will store the packets to be printed.
    struct sockaddr_in discovery_address;       // The address of the discovery socket.
    size_t discovery_address_len;               // The length of the discovery socket address.
    struct pollfd radio_fds[2];                 // The file descriptors of discovery and radio socket.
    struct pollfd ui_fds[1 + MAX_CONNECTIONS];  // The file descriptors of the UI sockets.
    byte_t ui_buffer[UI_BUF_SIZE];              // Smaller buffer for UI messages.
    stations_t stations;                        // The set of stations.
    struct ip_mreq multicast_request;           // The multicast request for joining the group.
    stations_iterator_t picked_station;         // Currently picked radio station.
    std::mutex stations_mutex;                  // Mutex for stations.
    size_t picked_index;                        // Index of the currently picked radio station.

    bool pick_favourite_station() {
        size_t index = 0;
        for (auto station = stations.begin(); station != stations.end(); station++) {
            if (station->has_name(params.name)) {
                drop_membership(&radio_fds[1].fd, &multicast_request);
                create_membership(&radio_fds[1], station->mcast_addr.c_str(), station->data_port, &multicast_request);
                picked_station = station;
                picked_index = index;
                packets_buffer.clear();
                syslog("Picked favourite station: %s", station->name.c_str());
                return true;
            }
            index++;
        }
        return false;
    }

    void pick_station(size_t index) {
        if (stations.empty() || picked_index == index) return;

        auto station = stations.begin();
        if (index > 0) std::advance(station, index);
        drop_membership(&radio_fds[1].fd, &multicast_request);
        create_membership(&radio_fds[1], station->mcast_addr.c_str(), station->data_port, &multicast_request);
        picked_station = station;
        picked_index = index;
        packets_buffer.clear();
        syslog("Picked station: %s", station->name.c_str());
    }

    void pick_best_station() {
        if (!pick_favourite_station()) pick_station(0);
    }

    size_t update_index() {
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
        auto station = stations.begin();
        while (station != stations.end()) {
            if (station->is_expired()) {
                if (picked_station == station) {
                    picked_station = stations.end();
                    picked_expired = true;
                }
                // Remove the station from the list.
                syslog("Station: %s expired", station->name.c_str());
                station = stations.erase(station);
            } else {
                station++;
            }
        }
        // Nothing changed, return.
        if (initial_size == stations.size()) return;
        // If the picked station expired, pick the best one else update the index.
        if (picked_expired) {
            pick_best_station();
        } else if (!stations.empty()) {
            picked_index = update_index();
        }
        notify_all();
    }

    void update_stations_and_pick(std::optional<Station> station_opt) {
        std::lock_guard<std::mutex> lock(stations_mutex);
        auto station = station_opt.value();
        stations.erase(station);
        stations.insert(station);
        // If this is the first station, pick it.
        if (picked_station == stations.end())
            pick_station(0);
        else if (station.has_name(params.name)) {
            pick_favourite_station();
        } else {
            picked_index = update_index();
        }
        notify_all();
    }

    void notify_all() {
        std::string menu = get_menu(stations, picked_index);
        for (int i = 1; i < 1 + MAX_CONNECTIONS; i++) {
            if (ui_fds[i].fd < 0) continue;
            send_menu(ui_fds[i].fd, menu);
        }
    }

public:
    explicit Receiver(ReceiverParameters &params) : params(params), buffer(), packets_buffer(params.buffer_size),
                                                    discovery_address(), discovery_address_len(0),
                                                    radio_fds(), ui_fds(), ui_buffer(), stations(),
                                                    multicast_request(), picked_station(stations.end()),
                                                    stations_mutex(), picked_index(0) {
        // Initialize structures for sending control packets.
        discovery_address = get_remote_address(params.discover_addr.c_str(), params.control_port, false);
        discovery_address_len = sizeof(discovery_address);
        // Discovery socket.
        radio_fds[0].fd = open_multicast_socket();
        radio_fds[0].events = POLLIN;
        // Picked radio socket.
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
                ssize_t read_length = recv(radio_fds[0].fd, buffer, BSIZE, NO_FLAGS);
                if (read_length < 0) continue;

                buffer[read_length] = '\0';
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
        ssize_t message_len = sizeof(IAC_WILL_ECHO) / sizeof(char);
        while (true) {
            int res = poll(ui_fds, 1 + MAX_CONNECTIONS, -1);
            if (res < 0) PRINT_ERRNO();

            // Accept new connections.
            if (ui_fds[0].revents & POLLIN) {
                int client_fd = accept(ui_fds[0].fd, nullptr, nullptr);
                if (client_fd < 0) continue;

                if (!send_init_message(client_fd, IAC_WILL_ECHO, message_len) ||
                    !send_init_message(client_fd, IAC_WILL_SUPPRESS_GO_AHEAD, message_len)) {
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
                if (ui_fds[i].fd == -1) continue;
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
                    size_t index = MAX_CONNECTIONS + 1;
                    if (isUp(read_length, ui_buffer)) {
                        index = (picked_index + stations.size() - 1) % stations.size();
                    } else if (isDown(read_length, ui_buffer)) {
                        index = (picked_index + 1) % stations.size();
                    } else if (isQuit(read_length, ui_buffer)) {
                        CHECK_ERRNO(close(ui_fds[i].fd));
                        ui_fds[i].fd = -1;
                    }

                    if (index == MAX_CONNECTIONS + 1) continue;
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
            sendto(radio_fds[0].fd, LOOKUP, lookup_msg_len, NO_FLAGS,
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
            sendto(radio_fds[0].fd, request_msg.c_str(), request_msg.size(), NO_FLAGS,
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