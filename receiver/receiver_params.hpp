#ifndef RECEIVER_PARAMS_HPP
#define RECEIVER_PARAMS_HPP

#include <boost/program_options.hpp>
#include <iostream>
#include <string>
#include "../utils/types.h"
#include "../utils/const.h"
#include "../utils/err.h"

struct ReceiverParameters {
    port_t data_port;
    buffer_size_t buffer_size;
};

namespace po = boost::program_options;

static void validate(const ReceiverParameters &params) {
    if (params.buffer_size <= 0) {
        fatal("Buffer size must be greater than 0");
    }
    // Some other validation...
}

ReceiverParameters parse(int argc, const char **argv) {
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help", "produce help message")
            ("data-port,P", po::value<port_t>()->default_value(DATA_PORT), "set the receiver's port")
            ("buffer-size,b", po::value<buffer_size_t>()->default_value(BSIZE), "set the buffer size");

    ReceiverParameters params{};
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            exit(EXIT_SUCCESS);
        }

        params.data_port = vm["data-port"].as<port_t>();
        params.buffer_size = vm["buffer-size"].as<buffer_size_t>();
    } catch (po::error &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    validate(params);
    return params;
}

#endif // RECEIVER_PARAMS_HPP