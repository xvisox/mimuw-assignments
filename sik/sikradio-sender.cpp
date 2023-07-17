#include "sender/sender_utility.hpp"
#include "sender/sender_params.hpp"
#include "sender/sender.hpp"

int main(int argc, const char **argv) {
    SenderParameters params = parse(argc, argv);
    Sender sender(params);

    sender.run();

    return 0;
}
