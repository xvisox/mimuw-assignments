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

namespace {
    using Hasher = struct Hasher;
    using sequence_t = std::pair<std::vector<uint64_t>, unsigned long>;
    using hash_function_t = uint64_t (*)(uint64_t const *, size_t);
    using hash_functions_t = std::unordered_map<unsigned long, hash_function_t>;
    using hash_tbl_t = std::unordered_set<sequence_t, Hasher>;
    using hash_tbls_t = std::unordered_map<unsigned long, hash_tbl_t>;

    unsigned long nextId = 0;
    hash_functions_t hashFunctions;
    hash_tbls_t hashTables;

    struct Hasher {
        size_t operator()(const sequence_t& sequence) const {
            hash_functions_t::iterator it = hashFunctions.find(sequence.second);
            return it->second(&sequence.first[0], sequence.first.size());
        }
    };

    std::string seq_to_string(uint64_t const * seq, size_t size) {
        if (seq == NULL) {
            std::string s = "NULL";
            return s;
        }

        std::stringstream ss;

        ss << '\"';

        if (size > 0) {
            for(size_t i = 0; i < size - 1; i++)
                ss << seq[i] << ' ';

            ss << seq[size - 1];
        }

        ss << '\"';

        return ss.str();
    }

    void print_input_1(const char * function_name,
                       hash_function_t hash_function) {
        std::cerr << function_name << '(' << hash_function << ')'
                  << std::endl;
    }

    void print_input_2(const char * function_name, unsigned long id) {
        std::cerr << function_name << '(' << id << ')' << std::endl;
    }

    void print_input_3(const char * function_name, unsigned long id,
                       uint64_t const * seq, size_t size) {
        std::cerr << function_name << '(' << id << ", "
                  << seq_to_string(seq, size) << ", " << size << ')'
                  << std::endl;
    }

    void print_operation_1(const char * function_name, unsigned long id,
                           const char * info) {
        std::cerr << function_name << ": hash table #" << id << ' ' << info
                  << std::endl;
    }

    void print_operation_2(const char * function_name, unsigned long id,
                           const char * info_1, size_t size,
                           const char * info_2) {
        std::cerr << function_name << ": hash table #" << id << ' ' << info_1
                  << ' ' << size << ' ' << info_2 << std::endl;
    }

    void print_operation_3(const char * function_name, unsigned long id,
                       const char * info_1, uint64_t const * seq, size_t size,
                       const char * info_2) {
    std::cerr << function_name << ": hash table #" << id << info_1
              << ' ' << seq_to_string(seq, size) << ' ' << info_2 << std::endl;
    }

    bool check_input(const char * function_name, uint64_t const * seq,
                     size_t size) {
        bool correct = true;

        if (seq == NULL) {
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
} /* anonymous namespace */

unsigned long hash_create(hash_function_t hash_function) {
    assert(hash_function != NULL);

    if (debug)
        print_input_1(__func__, hash_function);

    hash_tbl_t hash_tbl;
    hashFunctions[nextId] = hash_function;
    hashTables[nextId] = hash_tbl;

    if (debug)
        print_operation_1(__func__, nextId, "created");

    return nextId++;
}

void hash_delete(unsigned long id) {
    if (debug)
        print_input_2(__func__, id);

    hash_tbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end()) {
        if (debug)
            print_operation_1(__func__, id, "does not exist");
    } else {
        hashFunctions.erase(id);
        hashTables.erase(it);

        if (debug)
            print_operation_1(__func__, id, "deleted");
    }
}

size_t hash_size(unsigned long id) {
    if (debug)
        print_input_2(__func__, id);

    hash_tbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end()) {
        if (debug)
            print_operation_1(__func__, id, "does not exist");

        return 0;
    } else {
        if (debug)
            print_operation_2(__func__, id, "contains", it->second.size(), "element(s)");

        return it->second.size();
    }
}

bool hash_insert(unsigned long id, uint64_t const * seq, size_t size) {
    if (debug)
        print_input_3(__func__, id, seq, size);

    bool correct = check_input(__func__, seq, size);

    if (!correct)
        return false;

    hash_tbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end()) {
        if (debug)
            print_operation_1(__func__, id, "does not exist");

        return false;
    }

    std::vector<uint64_t> vec(seq, seq + size);
    sequence_t sequence = make_pair(vec, id);

    if (it->second.find(sequence) != it->second.end()) {
        if (debug)
            print_operation_3(__func__, id, ", sequence", seq, size, "was present");

        return false;
    }

    it->second.insert(sequence);

    if (debug)
        print_operation_3(__func__, id, ", sequence", seq, size, "inserted");

    return true;
}

bool hash_remove(unsigned long id, uint64_t const * seq, size_t size) {
    if (debug)
        print_input_3(__func__, id, seq, size);

    bool correct = check_input(__func__, seq, size);

    if (!correct)
        return false;

    hash_tbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end()) {
        if (debug)
            print_operation_1(__func__, id, "does not exist");

        return false;
    }

    std::vector<uint64_t> vec(seq, seq + size);
    sequence_t sequence = make_pair(vec, id);

    if (it->second.find(sequence) == it->second.end()) {
        if (debug)
            print_operation_3(__func__, id, ", sequence", seq, size, "was not present");

        return false;
    }

    it->second.erase(sequence);

    if (debug)
        print_operation_3(__func__, id, ", sequence", seq, size, "removed");

    return true;
}

void hash_clear(unsigned long id) {
    if (debug)
        print_input_2(__func__, id);

    hash_tbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end()) {
        if (debug)
            print_operation_1(__func__, id, "does not exist");
    } else {
        if (it->second.size() == 0) {
            if (debug)
                print_operation_1(__func__, id, "was empty");
        } else {
            if (debug)
                print_operation_1(__func__, id, "cleared");

            it->second.clear();
        }
    }
}

bool hash_test(unsigned long id, uint64_t const * seq, size_t size) {
    if (debug)
        print_input_3(__func__, id, seq, size);

    bool correct = check_input(__func__, seq, size);

    if (!correct)
        return false;

    hash_tbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end()) {
        if (debug)
            print_operation_1(__func__, id, "does not exist");

        return false;
    }

    std::vector<uint64_t> vec(seq, seq + size);
    sequence_t sequence = make_pair(vec, id);

    if (it->second.find(sequence) == it->second.end()) {
        if (debug)
            print_operation_3(__func__, id, ", sequence", seq, size, "is not present");

        return false;
    } else {
        if (debug)
            print_operation_3(__func__, id, ", sequence", seq, size, "is present");

        return true;
    }
}
