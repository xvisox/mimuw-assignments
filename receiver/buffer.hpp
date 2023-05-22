#ifndef SIKRADIO_BUFFER_HPP
#define SIKRADIO_BUFFER_HPP

#include <mutex>
#include "session.hpp"
#include "../utils/types.h"

class Buffer {
private:
    std::mutex mutex;
    Session session;
    size_t capacity;            // Number of packets that can fit in the buffer.
    buffer_size_t buffer_size;  // Size of the buffer.
    packets_deque_t data;       // Received and yet not printed packets.
    packet_id_deque_t packets;  // Identifiers of above packets.
    packet_id_t BYTE_0;         // First byte number received.
    packet_id_t max_printed_id; // Max printed packet id.
    missed_ids_t missed_ids;    // Set of missed packet ids.

    void clean() {
        data.clear();
        packets.clear();
        missed_ids.clear();
    }

    void setup_if_necessary(packet_id_t id, session_id_t session_id, packet_size_t audio_data_size) {
        if (session.session_id >= session_id && session.is_initialized()) return;
        clean();
        // Initialize the session.
        session.state = SessionState::IN_PROGRESS;
        session.session_id = session_id;
        session.packet_size = audio_data_size;
        // Initialize the buffer.
        BYTE_0 = id;
        max_printed_id = id;
        capacity = (buffer_size / session.packet_size);
    }

    bool is_ready_to_print(packet_id_t last_packet_id) const {
        return last_packet_id >= BYTE_0 + (buffer_size * 3) / 4;
    }

    void prevent_overflow() {
        if (data.size() == capacity) pop();
    }

    void pop() {
        auto id = packets.front();
        data.pop_front();
        packets.pop_front();
        missed_ids.erase(id);
    }

    void append(std::optional<byte_vector_t> &packet_data, packet_id_t id) {
        if (data.empty()) {
            data.push_back(std::move(packet_data));
            packets.push_back(id);
            return;
        }
        // Add dummy packets if necessary.
        for (packet_id_t missed_packet = packets.back() + session.packet_size;
             missed_packet < id;
             missed_packet += session.packet_size) {
            prevent_overflow();
            data.emplace_back(std::nullopt);
            packets.push_back(missed_packet);
            missed_ids.insert(missed_packet);
        }
        // Add the actual packet.
        prevent_overflow();
        data.push_back(std::move(packet_data));
        packets.push_back(id);
    }

    void insert(std::optional<byte_vector_t> &packet_data, size_t position) {
        data[position] = std::move(packet_data);
    }

public:
    explicit Buffer(buffer_size_t buffer_size) : capacity(0), buffer_size(buffer_size), data(),
                                                 packets(), BYTE_0(0), max_printed_id(0) {}

    void add_packet(std::optional<byte_vector_t> &packet_data_opt, packet_size_t audio_data_size,
                    packet_id_t id, session_id_t session_id) {

        // Add the packet to the buffer.
        std::lock_guard<std::mutex> lock(mutex);
        setup_if_necessary(id, session_id, audio_data_size);
        // Ignore packets from previous sessions and ignore already printed packets.
        if (session_id < session.session_id || id <= max_printed_id) return;

        if (is_ready_to_print(id)) {
            session.state = SessionState::READY;
        }

        // Remove the packet from the set of missed packets if it was there.
        missed_ids.erase(id);
        if ((id - BYTE_0) % session.packet_size != 0) {
            // Probably will never happen.
            fatal("The first byte number is not a multiple of the packet size");
        } else if (packets.empty() || id > packets.back()) {
            // Add the packet to the end of the buffer.
            append(packet_data_opt, id);
        } else if (packets.front() <= id && id <= packets.back()) {
            // Add missing packet to the buffer.
            size_t position = (id - packets.front()) / session.packet_size;
            insert(packet_data_opt, position);
        } else {
            // Received packet is too old, ignore it.
            return;
        }
    }

    std::optional<byte_vector_t> read() {
        std::lock_guard<std::mutex> lock(mutex);
        if (session.state != SessionState::READY)
            return std::nullopt;

        if (data.empty() || !data.front().has_value()) {
            // Not the best idea, but it would be compatible with the task.
            // session.state = SessionState::NOT_INITIALIZED;
            return std::nullopt;
        }

        auto result = std::move(data.front().value());
        max_printed_id = std::max(max_printed_id, packets.front());
        pop();
        return result;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex);
        session.state = SessionState::NOT_INITIALIZED;
        clean();
    }

    missed_ids_t get_missed_ids() {
        std::lock_guard<std::mutex> lock(mutex);
        return missed_ids;
    }
};

#endif // SIKRADIO_BUFFER_HPP