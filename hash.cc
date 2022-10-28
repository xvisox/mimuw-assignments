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

#define debug_stream \
    if (debug) \
        cerr_stream()

namespace {
    using Hasher = struct Hasher;
    using sequence_t = std::pair<std::vector<uint64_t>, unsigned long>;
    using hash_function_t = uint64_t (*)(uint64_t const *, size_t);
    using hash_functions_t = std::unordered_map<unsigned long, hash_function_t>;
    using hash_tbl_t = std::unordered_set<sequence_t, Hasher>;
    using hash_tbls_t = std::unordered_map<unsigned long, hash_tbl_t>;

    unsigned long next_id = 0;

    std::ostream &cerr_stream() {
        static std::ios_base::Init initializer;
        return std::cerr;
    }

    hash_functions_t &get_hash_functions() {
        static hash_functions_t hash_functions;
        return hash_functions;
    }

    struct Hasher {
        size_t operator()(const sequence_t &sequence) const {
            auto it = get_hash_functions().find(sequence.second);
            return it->second(&sequence.first[0], sequence.first.size());
        }
    };

    hash_tbls_t &get_hash_tables() {
        static hash_tbls_t hash_tbls;
        return hash_tbls;
    }

    std::string seq_to_string(uint64_t const *seq, size_t size) {
        if (seq == nullptr) {
            return "NULL";
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

    void print_input_1(const char *function_name,
                       hash_function_t hash_function) {
        debug_stream << function_name << '(' << &hash_function << ')'
                     << std::endl;
    }

    void print_input_2(const char *function_name, unsigned long id) {
        debug_stream << function_name << '(' << id << ')' << std::endl;
    }

    void print_input_3(const char *function_name, unsigned long id,
                       uint64_t const *seq, size_t size) {
        debug_stream << function_name << '(' << id << ", "
                     << seq_to_string(seq, size) << ", " << size << ')'
                     << std::endl;
    }

    void print_operation_1(const char *function_name, unsigned long id,
                           const char *info) {
        debug_stream << function_name << ": hash table #" << id << ' ' << info
                     << std::endl;
    }

    void print_operation_2(const char *function_name, unsigned long id,
                           const char *info_1, size_t size,
                           const char *info_2) {
        debug_stream << function_name << ": hash table #" << id << ' '
                     << info_1 << ' ' << size << ' ' << info_2 << std::endl;
    }

    void print_operation_3(const char *function_name, unsigned long id,
                         const char *info_1, uint64_t const *seq, size_t size,
                         const char *info_2) {
        debug_stream << function_name << ": hash table #" << id << info_1
                     << ' ' << seq_to_string(seq, size) << ' ' << info_2
                     << std::endl;
    }

    bool check_input(const char *function_name, uint64_t const *seq,
                     size_t size) {
        bool correct = true;

        if (seq == nullptr) {
            debug_stream << function_name << ": invalid pointer (NULL)"
                         << std::endl;
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
        print_input_1(__func__, hash_function);

        hash_tbl_t hash_tbl;
        get_hash_functions()[next_id] = hash_function;
        get_hash_tables()[next_id] = hash_tbl;
        print_operation_1(__func__, next_id, "created");

        return next_id++;
    }

    void hash_delete(unsigned long id) {
        print_input_2(__func__, id);
        auto it = get_hash_tables().find(id);

        if (it == get_hash_tables().end()) {
            print_operation_1(__func__, id, "does not exist");
        } else {
            get_hash_functions().erase(id);
            get_hash_tables().erase(it);
            print_operation_1(__func__, id, "deleted");
        }
    }

    size_t hash_size(unsigned long id) {
        print_input_2(__func__, id);
        auto it = get_hash_tables().find(id);

        if (it == get_hash_tables().end()) {
            print_operation_1(__func__, id, "does not exist");
            return 0;
        } else {
            print_operation_2(__func__, id, "contains", it->second.size(),
                              "element(s)");
            return it->second.size();
        }
    }

    bool hash_insert(unsigned long id, uint64_t const *seq, size_t size) {
        print_input_3(__func__, id, seq, size);
        bool correct = check_input(__func__, seq, size);

        if (!correct)
            return false;

        auto it = get_hash_tables().find(id);

        if (it == get_hash_tables().end()) {
            print_operation_1(__func__, id, "does not exist");
            return false;
        }

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (it->second.find(sequence) != it->second.end()) {
            print_operation_3(__func__, id, ", sequence", seq, size,
                              "was present");
            return false;
        }

        it->second.insert(sequence);
        print_operation_3(__func__, id, ", sequence", seq, size, "inserted");

        return true;
    }

    bool hash_remove(unsigned long id, uint64_t const *seq, size_t size) {
        print_input_3(__func__, id, seq, size);
        bool correct = check_input(__func__, seq, size);

        if (!correct)
            return false;

        auto it = get_hash_tables().find(id);

        if (it == get_hash_tables().end()) {
            print_operation_1(__func__, id, "does not exist");
            return false;
        }

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (it->second.find(sequence) == it->second.end()) {
            print_operation_3(__func__, id, ", sequence", seq, size,
                              "was not present");
            return false;
        }

        it->second.erase(sequence);
        print_operation_3(__func__, id, ", sequence", seq, size, "removed");

        return true;
    }

    void hash_clear(unsigned long id) {
        print_input_2(__func__, id);
        auto it = get_hash_tables().find(id);

        if (it == get_hash_tables().end()) {
            print_operation_1(__func__, id, "does not exist");
        } else {
            if (it->second.empty()) {
                print_operation_1(__func__, id, "was empty");
            } else {
                print_operation_1(__func__, id, "cleared");
                it->second.clear();
            }
        }
    }

    bool hash_test(unsigned long id, uint64_t const *seq, size_t size) {
        print_input_3(__func__, id, seq, size);
        bool correct = check_input(__func__, seq, size);

        if (!correct)
            return false;

        auto it = get_hash_tables().find(id);

        if (it == get_hash_tables().end()) {
            print_operation_1(__func__, id, "does not exist");
            return false;
        }

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (it->second.find(sequence) == it->second.end()) {
            print_operation_3(__func__, id, ", sequence", seq, size,
                              "is not present");
            return false;
        } else {
            print_operation_3(__func__, id, ", sequence", seq, size,
                              "is present");
            return true;
        }
    }
}
