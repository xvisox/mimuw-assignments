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
    using hash_table_t = std::unordered_set<sequence_t, Hasher>;
    using hash_tables_t = std::unordered_map<unsigned long, hash_table_t>;

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
            auto hashFunctionIt = getHashFunctions().find(sequence.second);
            return hashFunctionIt->second(&sequence.first[0], sequence.first.size());
        }
    };

    hash_tables_t &getHashTables() {
        static hash_tables_t hashTables;
        return hashTables;
    }

    std::string seqToString(uint64_t const *seq, size_t size) {
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

    void logHashCreate(const char *functionName, hash_function_t hash_function) {
        debugStream << functionName << '(' << &hash_function << ')' << std::endl;
    }

    void logFunctionCall(const char *functionName, unsigned long id) {
        debugStream << functionName << '(' << id << ')' << std::endl;
    }

    void logInputSequence(const char *functionName, unsigned long id,
                          uint64_t const *seq, size_t size) {
        debugStream << functionName << '(' << id << ", "
                    << seqToString(seq, size) << ", " << size << ')'
                    << std::endl;
    }

    void logHashInfo(const char *functionName, unsigned long id,
                     const char *info) {
        debugStream << functionName << ": hash table #" << id << ' ' << info
                    << std::endl;
    }

    void logHashSize(const char *functionName, unsigned long id,
                     size_t size, const char *info_2) {
        debugStream << functionName << ": hash table #" << id << ' ' << "contains"
                    << ' ' << size << ' ' << info_2 << std::endl;
    }

    void logSequenceInfo(const char *functionName, unsigned long id,
                         uint64_t const *seq, size_t size,
                         const char *info_2) {
        debugStream << functionName << ": hash table #" << id << ", sequence"
                    << ' ' << seqToString(seq, size) << ' ' << info_2 << std::endl;
    }

    bool checkInput(const char *functionName, uint64_t const *seq, size_t size) {
        bool correct = true;

        if (seq == nullptr) {
            debugStream << functionName << ": invalid pointer (NULL)" << std::endl;
            correct = false;
        }

        if (size == 0) {
            debugStream << functionName << ": invalid size (0)" << std::endl;
            correct = false;
        }

        return correct;
    }
}

namespace jnp1 {
    unsigned long hash_create(hash_function_t hash_function) {
        assert(hash_function != nullptr);
        logHashCreate(__func__, hash_function);

        hash_table_t hash_table;
        getHashFunctions()[nextId] = hash_function;
        getHashTables()[nextId] = hash_table;

        logHashInfo(__func__, nextId, "created");
        return nextId++;
    }

    void hash_delete(unsigned long id) {
        logFunctionCall(__func__, id);

        auto hashTableIt = getHashTables().find(id);
        if (hashTableIt == getHashTables().end()) {
            logHashInfo(__func__, id, "does not exist");
        } else {
            getHashFunctions().erase(id);
            getHashTables().erase(hashTableIt);
            logHashInfo(__func__, id, "deleted");
        }
    }

    size_t hash_size(unsigned long id) {
        logFunctionCall(__func__, id);

        auto hashTableIt = getHashTables().find(id);
        if (hashTableIt == getHashTables().end()) {
            logHashInfo(__func__, id, "does not exist");
            return 0;
        } else {
            logHashSize(__func__, id, hashTableIt->second.size(), "element(s)");
            return hashTableIt->second.size();
        }
    }

    bool hash_insert(unsigned long id, uint64_t const *seq, size_t size) {
        logInputSequence(__func__, id, seq, size);
        bool correct = checkInput(__func__, seq, size);
        if (!correct) return false;

        auto hashTableIt = getHashTables().find(id);
        if (hashTableIt == getHashTables().end()) {
            logHashInfo(__func__, id, "does not exist");
            return false;
        }

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (hashTableIt->second.find(sequence) != hashTableIt->second.end()) {
            logSequenceInfo(__func__, id, seq, size, "was present");
            return false;
        }

        hashTableIt->second.insert(sequence);
        logSequenceInfo(__func__, id, seq, size, "inserted");

        return true;
    }

    bool hash_remove(unsigned long id, uint64_t const *seq, size_t size) {
        logInputSequence(__func__, id, seq, size);
        bool correct = checkInput(__func__, seq, size);
        if (!correct) return false;

        auto hashTableIt = getHashTables().find(id);
        if (hashTableIt == getHashTables().end()) {
            logHashInfo(__func__, id, "does not exist");
            return false;
        }

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (hashTableIt->second.find(sequence) == hashTableIt->second.end()) {
            logSequenceInfo(__func__, id, seq, size, "was not present");
            return false;
        }

        hashTableIt->second.erase(sequence);
        logSequenceInfo(__func__, id, seq, size, "removed");

        return true;
    }

    void hash_clear(unsigned long id) {
        logFunctionCall(__func__, id);

        auto hashTableIt = getHashTables().find(id);

        if (hashTableIt == getHashTables().end()) {
            logHashInfo(__func__, id, "does not exist");
        } else {
            if (hashTableIt->second.empty()) {
                logHashInfo(__func__, id, "was empty");
            } else {
                logHashInfo(__func__, id, "cleared");
                hashTableIt->second.clear();
            }
        }
    }

    bool hash_test(unsigned long id, uint64_t const *seq, size_t size) {
        logInputSequence(__func__, id, seq, size);
        bool correct = checkInput(__func__, seq, size);
        if (!correct) return false;

        auto hashTableIt = getHashTables().find(id);
        if (hashTableIt == getHashTables().end()) {
            logHashInfo(__func__, id, "does not exist");
            return false;
        }

        std::vector<uint64_t> vec(seq, seq + size);
        sequence_t sequence = make_pair(vec, id);

        if (hashTableIt->second.find(sequence) == hashTableIt->second.end()) {
            logSequenceInfo(__func__, id, seq, size, "is not present");
            return false;
        } else {
            logSequenceInfo(__func__, id, seq, size, "is present");
            return true;
        }
    }
}
