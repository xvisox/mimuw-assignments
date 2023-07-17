#ifndef RECEIVER_PARAMS_HPP
#define RECEIVER_PARAMS_HPP

#include <boost/program_options.hpp>
#include <iostream>
#include <string>
#include "../utils/types.h"
#include "../utils/const.h"
#include "../utils/err.h"

struct ReceiverParameters {
    std::string discover_addr;
    std::string name;
    port_t control_port;
    port_t ui_port;
    buffer_size_t buffer_size;
    milliseconds_t rtime;
};

namespace po = boost::program_options;

static void validate_port(s_port_t port) {
    if (port < 1024 || port > UINT16_MAX) {
        fatal("Port must be between 1024 and 65535");
    }
}

// Note: Discover address will be validated in the get_remote_address() function.
static void validate(const ReceiverParameters &params) {
    if (params.buffer_size <= 0) {
        fatal("Buffer size must be greater than 0");
    }
    if (params.rtime <= 0) {
        fatal("Retransmission time must be greater than 0");
    }
    if (params.name.empty() || params.name.size() > 64) {
        fatal("Name must be between 1 and 64 characters long");
    }
    syslog("Receiver parameters: %s %s %d %d %ld %ld",
           params.discover_addr.c_str(), params.name.c_str(), params.control_port, params.ui_port,
           params.buffer_size, params.rtime);
}

ReceiverParameters parse(int argc, const char **argv) {
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help", "produce help message")
            (",d", po::value<std::string>()->default_value(DISCOVER_ADDR), "set the discovery IP address")
            (",C", po::value<s_port_t>()->default_value(CTRL_PORT), "set the control port")
            (",U", po::value<s_port_t>()->default_value(UI_PORT), "set the user interface port")
            (",b", po::value<buffer_size_t>()->default_value(BSIZE), "set the buffer size")
            (",R", po::value<milliseconds_t>()->default_value(RTIME), "set the retransmission time")
            (",n", po::value<std::string>()->default_value(NO_NAME), "set the name of the sender station");

    ReceiverParameters params{};
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            exit(EXIT_SUCCESS);
        }

        // Validate ui and control ports.
        s_port_t ui_port = vm["-U"].as<s_port_t>();
        s_port_t control_port = vm["-C"].as<s_port_t>();
        validate_port(ui_port);
        validate_port(control_port);

        params.name = vm["-n"].as<std::string>();
        params.discover_addr = vm["-d"].as<std::string>();
        params.control_port = (port_t) control_port;
        params.ui_port = (port_t) ui_port;
        params.buffer_size = vm["-b"].as<buffer_size_t>();
        params.rtime = vm["-R"].as<milliseconds_t>();
    } catch (po::error &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    validate(params);
    return params;
}

#endif // RECEIVER_PARAMS_HPP