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
public:
    SessionState state;
    session_id_t session_id;
    packet_size_t packet_size;

    explicit Session() : state(SessionState::NOT_INITIALIZED), session_id(0), packet_size(0) {}

    bool is_initialized() const {
        return state != SessionState::NOT_INITIALIZED;
    }
};

#endif // SESSION_HPP