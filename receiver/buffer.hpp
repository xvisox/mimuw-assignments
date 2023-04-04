#ifndef BUFFER_H
#define BUFFER_H

#include <mutex>
#include "../utils/types.h"

enum class BufferState {
    EMPTY,
    IN_PROGRESS,
    READY
};

class Buffer {
private:
    std::mutex mutex;
    BufferState state;
    buffer_size_t buffer_size;
    packet_size_t packet_size;
    size_t capacity;            // Number of packets that can fit in the buffer.
    packet_id_t BYTE_0;         // First byte number received.
    packet_id_t MAX_BYTE;       // Last byte number received.
    packet_id_deque_t packets;  // Identifiers of received packets.
    packets_deque_t data;       // Received and yet not printed packets.
public:

};

#endif // BUFFER_H