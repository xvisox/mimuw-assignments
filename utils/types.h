#ifndef SIKRADIO_TYPES_H
#define SIKRADIO_TYPES_H

#include <cstdint>
#include <vector>
#include <deque>

typedef uint16_t port_t;
typedef uint64_t session_id_t;
typedef uint64_t byte_num_t;
typedef uint64_t buffer_size_t;
typedef uint64_t packet_size_t;
typedef uint64_t packet_id_t;
typedef char byte_t;
typedef std::vector<byte_t> byte_vector_t;
typedef std::deque<byte_vector_t> packets_deque_t;
typedef std::deque<packet_id_t> packet_id_deque_t;

#endif //SIKRADIO_TYPES_H