#ifndef BUFFER_H
#define BUFFER_H

#include <mutex>
#include "../utils/audio_packet.h"
#include "../utils/types.h"
#include "session.hpp"

class Buffer {
private:
    std::mutex mutex;
    Session session;
    size_t capacity;            // Number of packets that can fit in the buffer.
    buffer_size_t buffer_size;  // Size of the buffer.
    packets_deque_t data;       // Received and yet not printed packets.
    packet_id_deque_t packets;  // Identifiers of above packets.
    packet_id_t BYTE_0;         // First byte number received.

    void setup_if_necessary(struct AudioPacket *packet, size_t audio_data_size) {
        if (session.is_initialized()) return;
        // Initialize the session.
        session.state = SessionState::IN_PROGRESS;
        session.session_id = packet->session_id;
        session.packet_size = audio_data_size;
        // Initialize the buffer.
        BYTE_0 = packet->first_byte_num;
        capacity = (buffer_size / session.packet_size);
    }

    bool is_ready_to_print(struct AudioPacket *last_packet) const {
        return last_packet->first_byte_num >= BYTE_0 + (buffer_size * 3) / 4;
    }

    void prevent_overflow() {
        if (data.size() == capacity) {
            data.pop_front();
            packets.pop_front();
        }
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
    explicit Buffer(buffer_size_t buffer_size) : buffer_size(buffer_size), data(), packets(),
                                                 BYTE_0(0), capacity(0) {}

    void add_packet(struct AudioPacket *packet, size_t bytes) {
        std::lock_guard<std::mutex> lock(mutex);
        size_t audio_data_size = bytes - sizeof(struct AudioPacket);
        setup_if_necessary(packet, audio_data_size);
        if (is_ready_to_print(packet)) {
            session.state = SessionState::READY;
        }

        // Convert the audio data to a vector of bytes.
        std::optional<byte_vector_t> packet_data;
        for (size_t i = 0; i < audio_data_size; i++) {
            packet_data->push_back(packet->audio_data[i]);
        }

        if (packet->first_byte_num % session.packet_size != 0) {
            // TODO: What to do in this case?
            fatal("The first byte number is not a multiple of the packet size");
        } else if (packets.empty() || packet->first_byte_num > packets.back()) {
            // Add the packet to the end of the buffer.
            append(packet_data, packet->first_byte_num);
        } else if (packets.front() <= packet->first_byte_num && packet->first_byte_num <= packets.back()) {
            // Add missing packet to the buffer.
            size_t position = (packet->first_byte_num - packets.front()) / session.packet_size;
            insert(packet_data, position);
        }
        // Print missing packets before new packet.
        packet_id_t n = (packet->first_byte_num - packets.front()) / session.packet_size;
        for (packet_id_t i = 0; i < n; i++) {
            if (data[i].has_value()) continue;
            std::cerr << "MISSING: BEFORE " << packet->first_byte_num << " EXPECTED " << packets[i] << std::endl;
        }
    }

    byte_vector_t read() {
        std::lock_guard<std::mutex> lock(mutex);
        // FIXME: What to do if the buffer is empty?
        if (session.state != SessionState::READY || data.empty() || !data.front().has_value())
            throw std::runtime_error("Buffer is not ready to read");

        auto result = std::move(data.front().value());
        data.pop_front();
        packets.pop_front();
        return result;
    }
};

#endif // BUFFER_H