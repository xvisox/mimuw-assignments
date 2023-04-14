#ifndef PACKETS_QUEUE_HPP
#define PACKETS_QUEUE_HPP

#include <queue>
#include <mutex>
#include <cstring>
#include "../utils/audio_packet.h"
#include "../utils/err.h"

class PacketsQueue {
private:
    std::queue<struct AudioPacket *> queue;
    std::mutex mutex;

public:
    void push(struct AudioPacket *packet) {
        std::lock_guard <std::mutex> lock(mutex);
        // Push a copy of the packet to the queue.
        if (packet != nullptr)
            queue.push(packet);
        else
            queue.push(nullptr);
    }

    struct AudioPacket *pop(bool *success) {
        std::lock_guard <std::mutex> lock(mutex);
        if (queue.empty()) {
            *success = false;
            return nullptr;
        }
        // Pop the packet from the queue.
        struct AudioPacket *packet = queue.front();
        queue.pop();
        *success = true;
        return packet;
    }
};

#endif //PACKETS_QUEUE_HPP