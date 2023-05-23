#ifndef SENDER_PARAMS_HPP
#define SENDER_PARAMS_HPP

#include <string>
#include <boost/program_options.hpp>
#include <iostream>
#include "../utils/types.h"
#include "../utils/const.h"
#include "../utils/err.h"

struct SenderParameters {
    std::string mcast_addr;
    std::string name;
    port_t data_port;
    port_t control_port;
    packet_size_t psize;
    packet_size_t fsize;
    milliseconds_t rtime;
};

namespace po = boost::program_options;

static void validate_port(s_port_t port) {
    if (port <= 1024 || port > UINT16_MAX) {
        fatal("Port must be between 1025 and 65535");
    }
}

// Note: Multicast address validation is done in get_remote_address().
static void validate(const SenderParameters &params) {
    if (params.psize <= 0 || params.psize > UINT16_MAX) {
        fatal("Packet size must be between 1 and 65535");
    }
    if (params.fsize <= 0) {
        fatal("FIFO size must be greater than 0");
    }
    if (params.rtime <= 0) {
        fatal("Retransmission time must be greater than 0");
    }
    if (params.name.empty() || params.name.size() > 64) {
        fatal("Name must be between 1 and 64 characters long");
    }
    syslog("Sender parameters: %s %s %d %d %ld %ld %ld",
           params.mcast_addr.c_str(), params.name.c_str(), params.data_port, params.control_port,
           params.psize, params.fsize, params.rtime);
}

SenderParameters parse(int argc, const char **argv) {
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help", "produce help message")
            (",a", po::value<std::string>()->required(), "set the multicast IP address")
            (",n", po::value<std::string>()->default_value(DEFAULT_NAME), "set the name of the sender")
            (",P", po::value<s_port_t>()->default_value(DATA_PORT), "set the receiver's port")
            (",C", po::value<s_port_t>()->default_value(CTRL_PORT), "set the control port")
            (",p", po::value<packet_size_t>()->default_value(PSIZE), "set the packet size")
            (",f", po::value<buffer_size_t>()->default_value(FSIZE), "set the fifo size")
            (",R", po::value<milliseconds_t>()->default_value(RTIME), "set the retransmission time");

    SenderParameters params{};
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            exit(EXIT_SUCCESS);
        }

        // Validate data and control ports.
        s_port_t data_port = vm["-P"].as<s_port_t>();
        s_port_t control_port = vm["-C"].as<s_port_t>();
        validate_port(data_port);
        validate_port(control_port);

        params.mcast_addr = vm["-a"].as<std::string>();
        params.name = vm["-n"].as<std::string>();
        params.data_port = (port_t) data_port;
        params.control_port = (port_t) control_port;
        params.psize = vm["-p"].as<packet_size_t>();
        params.fsize = vm["-f"].as<buffer_size_t>();
        params.rtime = vm["-R"].as<milliseconds_t>();
    } catch (po::error &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    validate(params);
    return params;
}

#endif // SENDER_PARAMS_HPP