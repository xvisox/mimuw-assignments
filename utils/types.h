#ifndef SIKRADIO_TYPES_H
#define SIKRADIO_TYPES_H

#include <cstdint>
#include <vector>
#include <deque>
#include <optional>
#include <unordered_set>

typedef uint16_t port_t;
typedef int64_t session_id_t;
typedef uint64_t buffer_size_t;
typedef ssize_t packet_size_t;
typedef uint64_t packet_id_t;
typedef uint64_t milliseconds_t;
typedef char byte_t;
typedef int socket_t;
typedef std::vector<byte_t> byte_vector_t;
typedef std::deque<std::optional<byte_vector_t>> packets_deque_t;
typedef std::deque<packet_id_t> packet_id_deque_t;
typedef std::unordered_set<packet_id_t> missed_ids_t;

#endif //SIKRADIO_TYPES_H