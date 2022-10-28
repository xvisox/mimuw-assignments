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

#define debugStream if (!debug) {} else cerrStream()

namespace {
    using Hasher = struct Hasher;
    using sequence_t = std::pair<std::vector<uint64_t>, unsigned long>;
    using hash_function_t = uint64_t (*)(uint64_t const *, size_t);
    using hash_functions_t = std::unordered_map<unsigned long, hash_function_t>;
    using hash_tbl_t = std::unordered_set<sequence_t, Hasher>;
    using hash_tbls_t = std::unordered_map<unsigned long, hash_tbl_t>;

    unsigned long nextId = 0;

    std::ostream &cerrStream() {
        static std::ios_base::Init mInitializer;
        return std::cerr;
    }

    hash_functions_t &getHashFunctions() {
        static hash_functions_t hashFunctions;
        return hashFunctions;
    }

    struct Hasher {
        size_t operator()(const sequence_t &sequence) const {
            auto it = getHashFunctions().find(sequence.second);
            return it->second(&sequence.first[0], sequence.first.size());
        }
    };

    hash_tbls_t &getHashTables() {
        static hash_tbls_t hashTbls;
        return hashTbls;
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

    void printInput1(const char *function_name, hash_function_t hash_function) {
        debugStream << function_name << '(' << &hash_function << ')' << std::endl;
    }

    void printInput2(const char *function_name, unsigned long id) {
        debugStream << function_name << '(' << id << ')' << std::endl;
    }

    void printInput3(const char *function_name, unsigned long id,
                     uint64_t const *seq, size_t size) {
        debugStream << function_name << '(' << id << ", "
                    << seq_to_string(seq, size) << ", " << size << ')'
                    << std::endl;
    }

    void printOperation1(const char *function_name, unsigned long id,
                         const char *info) {
        debugStream << function_name << ": hash table #" << id << ' ' << info
                    << std::endl;
    }

    void printOperation2(const char *function_name, unsigned long id,
                         const char *info_1, size_t size,
                         const char *info_2) {
        debugStream << function_name << ": hash table #" << id << ' ' << info_1
                    << ' ' << size << ' ' << info_2 << std::endl;
    }

    void printOperation3(const char *function_name, unsigned long id,
                         const char *info_1, uint64_t const *seq, size_t size,
                         const char *info_2) {
        debugStream << function_name << ": hash table #" << id << info_1
                    << ' ' << seq_to_string(seq, size) << ' ' << info_2 << std::endl;
    }

    bool checkInput(const char *function_name, uint64_t const *seq, size_t size) {
        bool correct = true;

        if (seq == nullptr) {
            debugStream << function_name << ": invalid pointer (NULL)" << std::endl;
            correct = false;
        }

        if (size == 0) {
            debugStream << function_name << ": invalid size (0)" << std::endl;
            correct = false;
        }

        return correct;
    }
}

namespace jnp1 {
    unsigned long hash_create(hash_function_t hash_function) {
        assert(hash_function != nullptr);
        printInput1(__func__, hash_function);

        hash_tbl_t hash_tbl;
        getHashFunctions()[nextId] = hash_function;
        getHashTables()[nextId] = hash_tbl;

        printOperation1(__func__, nextId, "created");
        return nextId++;
    }

    void hash_delete(unsigned long id) {
        printInput2(__func__, id);

        auto it = getHashTables().find(id);
        if (it == getHashTables().end()) {
            printOperation1(__func__, id, "does not exist");
        } else {
            getHashFunctions().erase(id);
            getHashTables().erase(it);
            printOperation1(__func__, id, "deleted");
        }
    }

    size_t hash_size(unsigned long id) {
        printInput2(__func__, id);

        auto it = getHashTables().find(id);
        if (it == getHashTables().end()) {
            printOperation1(__func__, id, "does not exist");
            return 0;
        } else {
            printOperation2(__func__, id, "contains", it->second.size(), "element(s)");
            return it->second.size();
        }
    }

    bool hash_insert(unsigned long id, uint64_t const *seq, size_t size) {
        printInput3(__func__, id, seq, size);
        bool correct = checkInput(__func__, seq, size);
        if (!correct) return false;

        auto it = getHashTables().find(id);
        if (it == getHashTables().end()) {
            printOperation1(__func__, id, "does not exist");
            return false;
        }

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (it->second.find(sequence) != it->second.end()) {
            printOperation3(__func__, id, ", sequence", seq, size, "was present");
            return false;
        }

        it->second.insert(sequence);
        printOperation3(__func__, id, ", sequence", seq, size, "inserted");

        return true;
    }

    bool hash_remove(unsigned long id, uint64_t const *seq, size_t size) {
        printInput3(__func__, id, seq, size);
        bool correct = checkInput(__func__, seq, size);
        if (!correct) return false;

        auto it = getHashTables().find(id);
        if (it == getHashTables().end()) {
            printOperation1(__func__, id, "does not exist");
            return false;
        }

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (it->second.find(sequence) == it->second.end()) {
            printOperation3(__func__, id, ", sequence", seq, size, "was not present");
            return false;
        }

        it->second.erase(sequence);
        printOperation3(__func__, id, ", sequence", seq, size, "removed");

        return true;
    }

    void hash_clear(unsigned long id) {
        printInput2(__func__, id);

        auto it = getHashTables().find(id);

        if (it == getHashTables().end()) {
            printOperation1(__func__, id, "does not exist");
        } else {
            if (it->second.empty()) {
                printOperation1(__func__, id, "was empty");
            } else {
                printOperation1(__func__, id, "cleared");
                it->second.clear();
            }
        }
    }

    bool hash_test(unsigned long id, uint64_t const *seq, size_t size) {
        printInput3(__func__, id, seq, size);
        bool correct = checkInput(__func__, seq, size);
        if (!correct) return false;

        auto hashTableIt = getHashTables().find(id);
        if (hashTableIt == getHashTables().end()) {
            printOperation1(__func__, id, "does not exist");
            return false;
        }

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (hashTableIt->second.find(sequence) == hashTableIt->second.end()) {
            printOperation3(__func__, id, ", sequence", seq, size, "is not present");
            return false;
        } else {
            printOperation3(__func__, id, ", sequence", seq, size, "is present");
            return true;
        }
    }
}
