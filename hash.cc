#include <vector>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

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

unsigned long hash_create(hash_function_t hash_function) {
    hash_tbl_t hash_tbl;
    hashFunctions[nextId] = hash_function;
    hashTables[nextId] = hash_tbl;
    return nextId++;
}

void hash_delete(unsigned long id) {
    hashFunctions.erase(id);
    hashTables.erase(id);
}

size_t hash_size(unsigned long id) {
    hash_tbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end())
        return 0;
    else
        return it->second.size();
}

bool hash_insert(unsigned long id, uint64_t const * seq, size_t size) {
    if (seq == NULL || size == 0)
        return false;

    hash_tbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end())
        return false;

    std::vector<uint64_t> vec(seq, seq + size);
    sequence_t sequence = make_pair(vec, id);

    if (it->second.find(sequence) != it->second.end())
        return false;

    it->second.insert(sequence);

    return true;
}

bool hash_remove(unsigned long id, uint64_t const * seq, size_t size) {
    if (seq == NULL || size == 0)
        return false;

    hash_tbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end())
        return false;

    std::vector<uint64_t> vec(seq, seq + size);
    sequence_t sequence = make_pair(vec, id);

    if (it->second.find(sequence) == it->second.end())
        return false;

    it->second.erase(sequence);

    return true;
}

void hash_clear(unsigned long id) {
    hash_tbls_t::iterator it = hashTables.find(id);

    if (it != hashTables.end())
        return it->second.clear();
}

bool hash_test(unsigned long id, uint64_t const * seq, size_t size) {
    if (seq == NULL || size == 0)
        return false;

    hash_tbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end())
        return false;

    std::vector<uint64_t> vec(seq, seq + size);
    sequence_t sequence = make_pair(vec, id);

    if (it->second.find(sequence) == it->second.end())
        return false;
    else
        return true;
}
