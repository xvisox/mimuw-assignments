#ifndef SIKRADIO_CACHE_HPP
#define SIKRADIO_CACHE_HPP

#include "../utils/types.h"
#include <unordered_map>
#include <unordered_set>
#include <mutex>

class PacketsCache {
private:
    std::mutex mutex;
    std::unordered_map<packet_id_t, byte_vector_t> cache;
    packet_id_t max_packet_id_diff;
public:
    explicit PacketsCache(packet_id_t max_packet_id_diff) : mutex(), cache(), max_packet_id_diff(max_packet_id_diff) {}

    void push(packet_id_t packet_id, const byte_vector_t &packet) {
        std::lock_guard<std::mutex> lock(mutex);
        cache.emplace(packet_id, packet);
        cache.erase(packet_id - max_packet_id_diff);
    }

    byte_vector_t &pop(packet_id_t packet_id) {
        std::lock_guard<std::mutex> lock(mutex);
        return cache.at(packet_id);
    }
};

class MissedPackets {
    std::mutex mutex;
    std::unordered_set<packet_id_t> missed_packets;
public:
    void push_all(std::vector<packet_id_t> &missed) {
        std::lock_guard<std::mutex> lock(mutex);
        for (auto &packet_id: missed) {
            missed_packets.emplace(packet_id);
        }
    }

    std::vector<packet_id_t> pop_all() {
        std::lock_guard<std::mutex> lock(mutex);
        std::vector<packet_id_t> result;
        std::copy(missed_packets.begin(), missed_packets.end(), std::back_inserter(result));
        missed_packets.clear();
        return result;
    }
};

#endif //SIKRADIO_CACHE_HPP