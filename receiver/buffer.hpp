#ifndef BUFFER_H
#define BUFFER_H

#include <mutex>
#include "../utils/audio_packet.h"
#include "../utils/types.h"

class Buffer {
private:
    std::mutex mutex;
    buffer_size_t buffer_size;  // Size of the buffer.
    size_t capacity;            // Number of packets that can fit in the buffer.
    packet_id_deque_t packets;  // Identifiers of received packets.
    packets_deque_t data;       // Received and yet not printed packets.
public:
};

#endif // BUFFER_H