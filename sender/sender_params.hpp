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

static void validate(const SenderParameters &params) {
    if (params.psize <= 0) {
        fatal("Packet size must be greater than 0");
    }
    // TODO: Some other validation...
}

SenderParameters parse(int argc, const char **argv) {
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help", "produce help message")
            (",a", po::value<std::string>()->required(), "set the multicast IP address")
            (",n", po::value<std::string>()->default_value(DEFAULT_NAME), "set the name of the sender")
            (",P", po::value<port_t>()->default_value(DATA_PORT), "set the receiver's port")
            (",C", po::value<port_t>()->default_value(CTRL_PORT), "set the control port")
            (",p", po::value<packet_size_t>()->default_value(PSIZE), "set the packet size")
            (",f", po::value<packet_size_t>()->default_value(FSIZE), "set the fifo size")
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

        params.mcast_addr = vm["-a"].as<std::string>();
        params.name = vm["-n"].as<std::string>();
        params.data_port = vm["-P"].as<port_t>();
        params.control_port = vm["-C"].as<port_t>();
        params.psize = vm["-p"].as<packet_size_t>();
        params.fsize = vm["-f"].as<packet_size_t>();
        params.rtime = vm["-R"].as<milliseconds_t>();
    } catch (po::error &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    validate(params);
    return params;
}

#endif // SENDER_PARAMS_HPP