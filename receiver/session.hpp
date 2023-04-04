#ifndef SESSION_HPP
#define SESSION_HPP

#include "../utils/types.h"
#include "../utils/audio_packet.h"

enum class SessionState {
    NOT_INITIALIZED,
    IN_PROGRESS,
    READY
};

class Session {
private:
    SessionState state;
    session_id_t session_id;
    packet_size_t packet_size;  // Size of a single packet.
    packet_id_t BYTE_0;         // First byte number received.
    packet_id_t MAX_BYTE;       // Last byte number received.

public:
    explicit Session() : state(SessionState::NOT_INITIALIZED), session_id(0), packet_size(0), BYTE_0(0), MAX_BYTE(0) {}

    void setup_if_not_initialized(struct AudioPacket *packet, size_t received_bytes) {
        if (state != SessionState::NOT_INITIALIZED) return;

        session_id = packet->session_id;
        packet_size = received_bytes - sizeof(struct AudioPacket);
        state = SessionState::IN_PROGRESS;
        BYTE_0 = packet->first_byte_num;
        MAX_BYTE = BYTE_0;
    }
};

#endif // SESSION_HPP