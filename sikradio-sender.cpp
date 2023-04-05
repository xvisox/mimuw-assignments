#include <ctime>
#include <iostream>

#include "sender/sender_utility.hpp"
#include "sender/sender_params.hpp"
#include "sender/sender.hpp"

int main(int argc, const char **argv) {
    SenderParameters params = parse(argc, argv);
    Sender sender(params);

    // FIXME: Remove this, only for debugging purposes.
    std::cout << params.dest_addr << std::endl;
    std::cout << params.data_port << std::endl;
    std::cout << params.psize << std::endl;
    std::cout << params.name << std::endl;

    sender.run();

    return 0;
}
