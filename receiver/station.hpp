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

    Station(std::string mcast_addr, std::string name, port_t data_port) : mcast_addr(std::move(mcast_addr)),
                                                                          name(std::move(name)),
                                                                          data_port(data_port),
                                                                          last_response(std::time(nullptr)) {}

    friend bool operator==(const Station &x, const Station &y) {
        return x.mcast_addr == y.mcast_addr && x.name == y.name;
    }

    [[nodiscard]] bool is_expired() const {
        return std::time(nullptr) - this->last_response > LOOKUP_EXPIRE_TIME_S;
    }

    [[nodiscard]] bool has_name(const std::string &desired_name) const {
        return this->name == desired_name;
    }

    friend std::strong_ordering operator<=>(const Station &x, const Station &y) {
        return x.name <=> y.name;
    }
};

#endif //SIKRADIO_STATION_HPP