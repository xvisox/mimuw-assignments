#include "receiver/receiver_params.hpp"
#include "receiver/receiver.hpp"

int main(int argc, const char **argv) {
    ReceiverParameters params = parse(argc, argv);
    Receiver receiver(params);

    receiver.run();

    return 0;
}
