#ifndef SENDER_PARAMS_H
#define SENDER_PARAMS_H

#include <string>
#include "../utils/types.h"

struct SenderParameters {
    std::string dest_addr;
    std::string name;
    port_t data_port;
    packet_size_t psize;
};

SenderParameters parse(int argc, const char **argv);

#endif // SENDER_PARAMS_H