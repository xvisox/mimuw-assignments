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
    byte_t buffer[BSIZE + 1];                   // The buffer will store raw data.
    byte_t ui_buffer[UI_BUF_SIZE + 1];          // Smaller buffer for UI messages.
    Buffer packets_buffer;                      // The buffer will store the packets to be printed.
    struct sockaddr_in discovery_address;       // The address of the discovery socket.
    size_t discovery_address_len;               // The length of the discovery socket address.
    struct pollfd radio_fds[2];                 // The file descriptors of discovery and radio socket.
    struct pollfd ui_fds[MAX_CONNECTIONS + 1];  // The file descriptors of the UI sockets.
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
        if (stations.empty()) return;

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
        if (params.name == NO_NAME) {
            pick_station(0);
        } else {
            pick_favourite_station();
        }
    }

    size_t update_index() {
        if (picked_station == stations.end())
            return SIZE_MAX;

        auto station = stations.begin();
        size_t index = 0;
        while (station != stations.end()) {
            if (station == picked_station)
                return index;
            station++;
            index++;
        }
        return SIZE_MAX;
    }

    void remove_expired_stations_and_pick() {
        bool picked_expired = false;
        size_t initial_size = stations.size();
        auto station = stations.begin();
        while (station != stations.end()) {
            if (station->is_expired()) {
                if (picked_station == station) {
                    drop_membership(&radio_fds[1].fd, &multicast_request);
                    picked_index = SIZE_MAX;
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
        auto station = station_opt.value();
        // If the station is already in the list, update it.
        auto it = stations.find(station);
        if (it != stations.end()) {
            if (picked_station == it) {
                syslog("Picked station: %s updated", station.name.c_str());
                stations.erase(it);
                picked_station = stations.insert(station).first;
            } else {
                syslog("Station: %s updated", station.name.c_str());
                stations.erase(it);
                stations.insert(station);
            }
            return;
        }

        syslog("Station: %s added", station.name.c_str());
        stations.insert(station);
        // Decide if the new station should be picked.
        if (picked_station == stations.end()) {
            pick_best_station();
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

    void accept_new_connection() {
        // These variables will be used to send the init message,
        // and they are static to avoid allocating them on the stack every time.
        static unsigned char IAC_WILL_ECHO[] = {255, 251, 1};
        static unsigned char IAC_WILL_SUPPRESS_GO_AHEAD[] = {255, 251, 3};
        static ssize_t message_len = sizeof(IAC_WILL_ECHO) / sizeof(char);

        int client_fd = accept(ui_fds[0].fd, nullptr, nullptr);
        if (client_fd < 0) {
            syslog("Error while accepting new connection");
            return;
        }

        if (!send_init_message(client_fd, IAC_WILL_ECHO, message_len) ||
            !send_init_message(client_fd, IAC_WILL_SUPPRESS_GO_AHEAD, message_len)) {
            syslog("Error while sending init message");
            CHECK_ERRNO(close(client_fd));
            return;
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
        if (!accepted) {
            syslog("Too many connections, closing new one");
            CHECK_ERRNO(close(client_fd));
        }
    }

    void handle_client_message(int i) {
        /*
         * Autor: Paweł Parys.
         * Jeśli to UI, to możemy rozłączyć.
         */
        size_t read_length = read(ui_fds[i].fd, ui_buffer, UI_BUF_SIZE);
        if (read_length == 0) {
            syslog("Client disconnected");
            CHECK_ERRNO(close(ui_fds[i].fd));
            ui_fds[i].fd = -1;
            return;
        }

        // If there are no stations, ignore the message.
        if (stations.empty()) return;

        std::lock_guard<std::mutex> lock(stations_mutex);
        size_t index = SIZE_MAX;
        if (isUp(read_length, ui_buffer)) {
            index = picked_station == stations.end() ? 0 : (picked_index + stations.size() - 1) % stations.size();
        } else if (isDown(read_length, ui_buffer)) {
            index = picked_station == stations.end() ? 0 : (picked_index + 1) % stations.size();
        } else if (isQuit(read_length, ui_buffer)) {
            CHECK_ERRNO(close(ui_fds[i].fd));
            ui_fds[i].fd = -1;
        }

        if (index == SIZE_MAX) return;
        pick_station(index);
        notify_all();
    }

public:
    explicit Receiver(ReceiverParameters &params) : params(params), buffer(), ui_buffer(),
                                                    packets_buffer(params.buffer_size),
                                                    discovery_address(), discovery_address_len(0),
                                                    radio_fds(), ui_fds(), stations(),
                                                    multicast_request(), picked_station(stations.end()),
                                                    stations_mutex(), picked_index(SIZE_MAX) {
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
            int res = poll(radio_fds, 2, RTIME);
            if (res < 0) PRINT_ERRNO();
            else {
                std::lock_guard<std::mutex> lock(stations_mutex);
                remove_expired_stations_and_pick();
            }

            if (radio_fds[0].revents & POLLIN) {
                /*
                 * Autor: Paweł Parys.
                 * Dla głównego gniazda UDP nie mam
                 * specjalnie pomysłu, może odczekać krótką chwilę i próbować ponownie.
                 * Można przy okazji wypisać błąd na stderr.
                 */
                struct sockaddr_in sender_address{};
                socklen_t sender_address_len = sizeof(sender_address);
                ssize_t read_length = recvfrom(radio_fds[0].fd, buffer, BSIZE, NO_FLAGS,
                                               (sockaddr *) &sender_address, &sender_address_len);
                if (read_length <= 0) {
                    syslog("Error while receiving discovery message");
                    continue;
                }
                if (buffer[read_length - 1] != '\n') {
                    syslog("Received control message without a newline character");
                    continue;
                }

                // Parse message to station info.
                buffer[read_length - 1] = '\0';
                auto station_opt = get_station(buffer, sender_address, sender_address_len);
                if (station_opt.has_value()) {
                    std::lock_guard<std::mutex> lock(stations_mutex);
                    update_stations_and_pick(station_opt);
                }
            }

            if (radio_fds[1].fd > 0 && radio_fds[1].revents & POLLIN) {
                /*
                 * Autor: Paweł Parys.
                 * Jeśli to odbiór danych, to możemy usunąć aktualną stację z
                 * listy i rozpocząć odbieranie od nowa.
                 */
                ssize_t read_length = recv(radio_fds[1].fd, buffer, BSIZE, NO_FLAGS);
                if (read_length <= empty_packet_size) {
                    syslog("Error while receiving audio data, changing station");
                    std::lock_guard<std::mutex> lock(stations_mutex);
                    size_t next_index = (picked_index + 1) % stations.size();
                    pick_station(next_index);
                    notify_all();
                    continue;
                }

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
        while (true) {
            int res = poll(ui_fds, 1 + MAX_CONNECTIONS, NO_TIMEOUT);
            if (res < 0) PRINT_ERRNO();

            // Accept new connections.
            if (ui_fds[0].revents & POLLIN) {
                accept_new_connection();
            }

            // Handle messages from clients.
            for (int i = 1; i < 1 + MAX_CONNECTIONS; ++i) {
                if (ui_fds[i].fd > 0 && ui_fds[i].revents & POLLIN) {
                    handle_client_message(i);
                }
            }
        }
    }

    [[noreturn]] void discovery_controller() {
        std::string lookup_msg = std::string(LOOKUP) + '\n';
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(LOOKUP_TIME_MS));
            // Send lookup message, ignore errors.
            sendto(radio_fds[0].fd, lookup_msg.c_str(), lookup_msg.size(), NO_FLAGS,
                   (struct sockaddr *) &discovery_address, discovery_address_len);
        }
    }

    [[noreturn]] void requests_controller() {
        std::string request_msg = std::string(REXMIT) + ' ';
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(params.rtime));
            auto missed_ids = packets_buffer.get_missed_ids();
            if (missed_ids.empty() || picked_station == stations.end()) continue;

            // Send request for missed packets, ignore errors.
            std::string request_str = get_request_str(missed_ids, request_msg);
            syslog("Sending request: %s", request_str.c_str());
            sendto(radio_fds[0].fd, request_str.data(), request_str.size(), NO_FLAGS,
                   (struct sockaddr *) &picked_station->address, picked_station->address_length);
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