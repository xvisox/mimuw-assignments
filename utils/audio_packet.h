#ifndef AUDIO_PACKET_H
#define AUDIO_PACKET_H

#include <cstdint>
#include "types.h"

struct __attribute__((__packed__)) AudioPacket {
    session_id_t session_id;
    packet_id_t first_byte_num;
    byte_t audio_data[];
};

#endif //AUDIO_PACKET_H