#ifndef SIKRADIO_STATION_HPP
#define SIKRADIO_STATION_HPP

#include <string>
#include <ctime>
#include <utility>
#include <netinet/in.h>
#include "../utils/types.h"

class Station {
public:
    std::string mcast_addr;
    std::string name;
    port_t data_port;
    std::time_t last_response;
    struct sockaddr_in address;
    socklen_t address_length;

    Station(std::string mcast_addr, std::string name, port_t data_port) : mcast_addr(std::move(mcast_addr)),
                                                                          name(std::move(name)),
                                                                          data_port(data_port),
                                                                          last_response(std::time(nullptr)),
                                                                          address(), address_length(0) {}

    [[nodiscard]] bool is_expired() const {
        return std::time(nullptr) - this->last_response > LOOKUP_EXPIRE_TIME_S;
    }

    [[nodiscard]] bool has_name(const std::string &desired_name) const {
        return this->name == desired_name;
    }

    /*
     * Autor: Paweł Parys.
     * Tym, niemniej przyjmijmy, że jeśli dwa nadajniki mają tę samą nazwę,
     * mcast_addr i data_port, to w odbiorcy można je utożsamić.
     */
    friend std::strong_ordering operator<=>(const Station &x, const Station &y) {
        if (x.name == y.name && x.mcast_addr == y.mcast_addr && x.data_port == y.data_port)
            return std::strong_ordering::equal;

        if (x.name != y.name) return x.name <=> y.name;
        if (x.mcast_addr != y.mcast_addr) return x.mcast_addr <=> y.mcast_addr;
        return x.data_port <=> y.data_port;
    }
};

#endif //SIKRADIO_STATION_HPP