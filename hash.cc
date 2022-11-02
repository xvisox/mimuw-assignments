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

namespace {
    using Hasher = struct Hasher;
    using sequence_t = std::vector<uint64_t>;
    using hash_function_t = uint64_t (*)(uint64_t const *, size_t);
    using hash_table_t = std::unordered_set<sequence_t, Hasher>;
    using hash_tables_t = std::unordered_map<unsigned long, hash_table_t>;

    struct Hasher {
        hash_function_t hash_function;

        Hasher(hash_function_t hash_function) {
            this->hash_function = hash_function;
        }

        size_t operator()(const sequence_t &sequence) const {
            return hash_function(std::data(sequence), sequence.size());
        }
    };

    hash_tables_t &get_hash_tables() {
        static hash_tables_t hash_tables;
        return hash_tables;
    }

    std::string seq_to_string(uint64_t const *seq, size_t size) { //  TODO dodanie & (?)
        if (seq == nullptr)
            return "NULL";

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

    void log_hash_create(const char *function_name,
                         hash_function_t hash_function) {
        std::cerr << function_name << '(' << &hash_function << ')'
                  << std::endl;
    }

    void log_function_call(const char *function_name, unsigned long id) {
        std::cerr << function_name << '(' << id << ')' << std::endl;
    }

    void log_input_sequence(const char *function_name, unsigned long id,
                            uint64_t const *seq, size_t size) {
        std::cerr << function_name << '(' << id << ", "
                  << seq_to_string(seq, size) << ", " << size << ')'
                  << std::endl;
    }

    void log_hash_info(const char *function_name, unsigned long id,
                       const char *info) {
        std::cerr << function_name << ": hash table #" << id << ' ' << info
                  << std::endl;
    }

    void log_hash_size(const char *function_name, unsigned long id,
                       size_t size) {
        std::cerr << function_name << ": hash table #" << id << ' '
                  << "contains" << ' ' << size << ' ' << "element(s)"
                  << std::endl;
    }

    void log_sequence_info(const char *function_name, unsigned long id,
                           uint64_t const *seq, size_t size,
                           const char *info_2) {
        std::cerr << function_name << ": hash table #" << id << ", sequence"
                  << ' ' << seq_to_string(seq, size) << ' ' << info_2
                  << std::endl;
    }

    bool check_input(const char *function_name, uint64_t const *seq,
                     size_t size) {
        bool correct = true;

        if (seq == nullptr) {
            if (debug)
                std::cerr << function_name << ": invalid pointer (NULL)"
                          << std::endl;

            correct = false;
        }

        if (size == 0) {
            if (debug)
                std::cerr << function_name << ": invalid size (0)" << std::endl;

            correct = false;
        }

        return correct;
    }
}

namespace jnp1 {
    unsigned long hash_create(hash_function_t hash_function) {
        static unsigned long next_id = 0;

        assert(hash_function != nullptr);
        if (debug) log_hash_create(__func__, hash_function);

        hash_table_t hash_table(0, Hasher(hash_function));
        get_hash_tables().insert(make_pair(next_id, hash_table));
        if (debug) log_hash_info(__func__, next_id, "created");
        return next_id++;
    }

    void hash_delete(unsigned long id) {
        if (debug) log_function_call(__func__, id);

        auto hash_tables_it = get_hash_tables().find(id);

        if (hash_tables_it == get_hash_tables().end()) {
            if (debug) log_hash_info(__func__, id, "does not exist");
        } else {
            get_hash_tables().erase(hash_tables_it);
            if (debug) log_hash_info(__func__, id, "deleted");
        }
    }

    size_t hash_size(unsigned long id) {
        if (debug) log_function_call(__func__, id);

        auto hash_tables_it = get_hash_tables().find(id);

        if (hash_tables_it == get_hash_tables().end()) {
            if (debug) log_hash_info(__func__, id, "does not exist");
            return 0;
        } else {
            if (debug) log_hash_size(__func__, id, hash_tables_it->second.size());
            return hash_tables_it->second.size();
        }
    }

    bool hash_insert(unsigned long id, uint64_t const *seq, size_t size) {
        if (debug) log_input_sequence(__func__, id, seq, size);

        bool correct = true;
        auto hash_tables_it = get_hash_tables().find(id);

        if (hash_tables_it == get_hash_tables().end()) {
            if (debug) log_hash_info(__func__, id, "does not exist");
            correct = false;
        }

        if (!check_input(__func__, seq, size) || !correct)
            return false;

        sequence_t sequence(seq, seq + size);

        if (hash_tables_it->second.find(sequence) !=
            hash_tables_it->second.end()) {
            if (debug) log_sequence_info(__func__, id, seq, size, "was present");
            return false;
        }

        hash_tables_it->second.insert(sequence);
        if (debug) log_sequence_info(__func__, id, seq, size, "inserted");

        return true;
    }

    bool hash_remove(unsigned long id, uint64_t const *seq, size_t size) {
        if (debug) log_input_sequence(__func__, id, seq, size);

        bool correct = true;
        auto hash_tables_it = get_hash_tables().find(id);

        if (hash_tables_it == get_hash_tables().end()) {
            if (debug) log_hash_info(__func__, id, "does not exist");
            correct = false;
        }

        if (!check_input(__func__, seq, size) || !correct)
            return false;

        sequence_t sequence(seq, seq + size);

        if (hash_tables_it->second.find(sequence) ==
            hash_tables_it->second.end()) {
            if (debug) log_sequence_info(__func__, id, seq, size, "was not present");
            return false;
        }

        hash_tables_it->second.erase(sequence);
        if (debug) log_sequence_info(__func__, id, seq, size, "removed");

        return true;
    }

    void hash_clear(unsigned long id) {
        if (debug) log_function_call(__func__, id);

        auto hash_tables_it = get_hash_tables().find(id);

        if (hash_tables_it == get_hash_tables().end()) {
            if (debug) log_hash_info(__func__, id, "does not exist");
        } else {
            if (hash_tables_it->second.empty()) {
                if (debug) log_hash_info(__func__, id, "was empty");
            } else {
                if (debug) log_hash_info(__func__, id, "cleared");
                hash_tables_it->second.clear();
            }
        }
    }

    bool hash_test(unsigned long id, uint64_t const *seq, size_t size) {
        if (debug) log_input_sequence(__func__, id, seq, size);

        bool correct = true;
        auto hash_tables_it = get_hash_tables().find(id);

        if (hash_tables_it == get_hash_tables().end()) {
            if (debug) log_hash_info(__func__, id, "does not exist");
            correct = false;
        }

        if (!check_input(__func__, seq, size) || !correct)
            return false;

        sequence_t sequence(seq, seq + size);

        if (hash_tables_it->second.find(sequence) ==
            hash_tables_it->second.end()) {
            if (debug) log_sequence_info(__func__, id, seq, size, "is not present");
            return false;
        } else {
            if (debug) log_sequence_info(__func__, id, seq, size, "is present");
            return true;
        }
    }
}
