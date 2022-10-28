#ifdef NDEBUG
bool const debug = false;
#else
bool const debug = true;
#endif

#include <vector>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include "hash.h"

#define debug_stream if (!debug) {} else cerr_stream()

namespace {
    using Hasher = struct Hasher;
    using sequence_t = std::pair<std::vector<uint64_t>, unsigned long>;
    using hash_function_t = uint64_t (*)(uint64_t const *, size_t);
    using hash_functions_t = std::unordered_map<unsigned long, hash_function_t>;
    using hash_table_t = std::unordered_set<sequence_t, Hasher>;
    using hash_tables_t = std::unordered_map<unsigned long, hash_table_t>;

    unsigned long nextId = 0;

    std::ostream &cerr_stream() {
        static std::ios_base::Init m_initializer;
        return std::cerr;
    }

    hash_functions_t &get_hash_functions() {
        static hash_functions_t hash_functions;
        return hash_functions;
    }

    struct Hasher {
        size_t operator()(const sequence_t &sequence) const {
            auto hash_function_it = get_hash_functions().find(sequence.second);
            return hash_function_it->second(&sequence.first[0], sequence.first.size());
        }
    };

    hash_tables_t &get_hash_tables() {
        static hash_tables_t hash_tables;
        return hash_tables;
    }

    std::string seq_to_string(uint64_t const *seq, size_t size) {
        if (seq == nullptr) {
            std::string s = "NULL";
            return s;
        }

        std::stringstream ss;
        ss << '\"';
        if (size > 0) {
            for (size_t i = 0; i < size - 1; i++)
                ss << seq[i] << ' ';

            ss << seq[size - 1];
        }
        ss << '\"';

        return ss.str();
    }

    void log_hash_create(const char *function_name, hash_function_t hash_function) {
        debug_stream << function_name << '(' << &hash_function << ')' << std::endl;
    }

    void log_function_call(const char *function_name, unsigned long id) {
        debug_stream << function_name << '(' << id << ')' << std::endl;
    }

    void log_input_sequence(const char *function_name, unsigned long id,
                            uint64_t const *seq, size_t size) {
        debug_stream << function_name << '(' << id << ", "
                     << seq_to_string(seq, size) << ", " << size << ')'
                     << std::endl;
    }

    void log_hash_info(const char *function_name, unsigned long id, const char *info) {
        debug_stream << function_name << ": hash table #" << id << ' ' << info
                     << std::endl;
    }

    void log_hash_size(const char *function_name, unsigned long id, size_t size) {
        debug_stream << function_name << ": hash table #" << id << ' ' << "contains"
                     << ' ' << size << ' ' << "element(s)" << std::endl;
    }

    void log_sequence_info(const char *function_name, unsigned long id,
                           uint64_t const *seq, size_t size,
                           const char *info_2) {
        debug_stream << function_name << ": hash table #" << id << ", sequence"
                     << ' ' << seq_to_string(seq, size) << ' ' << info_2 << std::endl;
    }

    bool check_input(const char *function_name, uint64_t const *seq, size_t size) {
        bool correct = true;

        if (seq == nullptr) {
            debug_stream << function_name << ": invalid pointer (NULL)" << std::endl;
            correct = false;
        }

        if (size == 0) {
            debug_stream << function_name << ": invalid size (0)" << std::endl;
            correct = false;
        }

        return correct;
    }
}

namespace jnp1 {
    unsigned long hash_create(hash_function_t hash_function) {
        assert(hash_function != nullptr);
        log_hash_create(__func__, hash_function);

        hash_table_t hash_table;
        get_hash_functions()[nextId] = hash_function;
        get_hash_tables()[nextId] = hash_table;

        log_hash_info(__func__, nextId, "created");
        return nextId++;
    }

    void hash_delete(unsigned long id) {
        log_function_call(__func__, id);

        auto hash_table_it = get_hash_tables().find(id);
        if (hash_table_it == get_hash_tables().end()) {
            log_hash_info(__func__, id, "does not exist");
        } else {
            get_hash_functions().erase(id);
            get_hash_tables().erase(hash_table_it);
            log_hash_info(__func__, id, "deleted");
        }
    }

    size_t hash_size(unsigned long id) {
        log_function_call(__func__, id);

        auto hash_table_it = get_hash_tables().find(id);
        if (hash_table_it == get_hash_tables().end()) {
            log_hash_info(__func__, id, "does not exist");
            return 0;
        } else {
            log_hash_size(__func__, id, hash_table_it->second.size());
            return hash_table_it->second.size();
        }
    }

    bool hash_insert(unsigned long id, uint64_t const *seq, size_t size) {
        log_input_sequence(__func__, id, seq, size);

        bool correct = true;
        auto hash_table_it = get_hash_tables().find(id);
        if (hash_table_it == get_hash_tables().end()) {
            log_hash_info(__func__, id, "does not exist");
            correct = false;
        }
        if (!check_input(__func__, seq, size) || !correct) return false;

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (hash_table_it->second.find(sequence) != hash_table_it->second.end()) {
            log_sequence_info(__func__, id, seq, size, "was present");
            return false;
        }

        hash_table_it->second.insert(sequence);
        log_sequence_info(__func__, id, seq, size, "inserted");

        return true;
    }

    bool hash_remove(unsigned long id, uint64_t const *seq, size_t size) {
        log_input_sequence(__func__, id, seq, size);

        bool correct = true;
        auto hash_table_it = get_hash_tables().find(id);
        if (hash_table_it == get_hash_tables().end()) {
            log_hash_info(__func__, id, "does not exist");
            correct = false;
        }
        if (!check_input(__func__, seq, size) || !correct) return false;

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (hash_table_it->second.find(sequence) == hash_table_it->second.end()) {
            log_sequence_info(__func__, id, seq, size, "was not present");
            return false;
        }

        hash_table_it->second.erase(sequence);
        log_sequence_info(__func__, id, seq, size, "removed");

        return true;
    }

    void hash_clear(unsigned long id) {
        log_function_call(__func__, id);

        auto hash_table_it = get_hash_tables().find(id);

        if (hash_table_it == get_hash_tables().end()) {
            log_hash_info(__func__, id, "does not exist");
        } else {
            if (hash_table_it->second.empty()) {
                log_hash_info(__func__, id, "was empty");
            } else {
                log_hash_info(__func__, id, "cleared");
                hash_table_it->second.clear();
            }
        }
    }

    bool hash_test(unsigned long id, uint64_t const *seq, size_t size) {
        log_input_sequence(__func__, id, seq, size);
        bool correct = true;

        auto hash_table_it = get_hash_tables().find(id);
        if (hash_table_it == get_hash_tables().end()) {
            log_hash_info(__func__, id, "does not exist");
            correct = false;
        }
        if (!check_input(__func__, seq, size) || !correct) return false;

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (hash_table_it->second.find(sequence) == hash_table_it->second.end()) {
            log_sequence_info(__func__, id, seq, size, "is not present");
            return false;
        } else {
            log_sequence_info(__func__, id, seq, size, "is present");
            return true;
        }
    }
}
