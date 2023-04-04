#ifndef SENDER_PARAMS_HPP
#define SENDER_PARAMS_HPP

#include <string>
#include <boost/program_options.hpp>
#include <iostream>
#include "../utils/types.h"
#include "../utils/const.h"
#include "../utils/err.h"

struct SenderParameters {
    std::string dest_addr;
    std::string name;
    port_t data_port;
    packet_size_t psize;
};

namespace po = boost::program_options;

static void validate(const SenderParameters &params) {
    if (params.psize <= 0) {
        fatal("Packet size must be greater than 0");
    }
    // Some other validation...
}

SenderParameters parse(int argc, const char **argv) {
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help", "produce help message")
            ("address,a", po::value<std::string>()->required(), "set the receiver's IP address")
            ("data-port,P", po::value<port_t>()->default_value(DATA_PORT), "set the receiver's port")
            ("packet-size,p", po::value<packet_size_t>()->default_value(PSIZE), "set the packet size")
            ("name,n", po::value<std::string>()->default_value(DEFAULT_NAME), "set the name of the sender");

    SenderParameters params{};
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            exit(EXIT_SUCCESS);
        }

        params.dest_addr = vm["address"].as<std::string>();
        params.data_port = vm["data-port"].as<port_t>();
        params.psize = vm["packet-size"].as<packet_size_t>();
        params.name = vm["name"].as<std::string>();
    } catch (po::error &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    validate(params);
    return params;
}

#endif // SENDER_PARAMS_HPP