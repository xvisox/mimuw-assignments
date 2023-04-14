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
        std::lock_guard<std::mutex> lock(mutex);
        // Push a copy of the packet to the queue.
        if (packet != nullptr)
            queue.push(packet);
        else
            queue.push(nullptr);
    }

    struct AudioPacket *pop() {
        std::lock_guard<std::mutex> lock(mutex);
        struct AudioPacket *packet = queue.front();
        queue.pop();
        return packet;
    }

    bool empty() {
        std::lock_guard<std::mutex> lock(mutex);
        return queue.empty();
    }
};

#endif //PACKETS_QUEUE_HPP