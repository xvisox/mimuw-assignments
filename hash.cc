#include <vector>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <unordered_map>
#include <unordered_set>

using namespace std;

using hash_function_t = uint64_t (*)(uint64_t const *, size_t);
using hash_functions_t = unordered_map<unsigned long, hash_function_t>;
using Sequence = struct Sequence;
using Hasher = struct Hasher;
using hashtbl_t = unordered_set<Sequence, Hasher>;
using hashtbls_t = unordered_map<unsigned long, hashtbl_t>;

unsigned long nextId = 0;
hash_functions_t hashFunctions;
hashtbls_t hashTables;

struct Sequence {
    vector<uint64_t> vec;
    unsigned long id;

    bool operator==(const Sequence& other) const {
        return vec == other.vec;
    }
};

struct Hasher {
    size_t operator()(const Sequence& seq) const {
        hash_functions_t::iterator it = hashFunctions.find(seq.id);
        return it->second(&seq.vec[0], seq.vec.size());
    }
};

unsigned long hash_create(hash_function_t hash_function) {
    hashtbl_t hashtbl;
    hashFunctions[nextId] = hash_function;
    hashTables[nextId] = hashtbl;
    return nextId++;
}

void hash_delete(unsigned long id) {
    hashTables.erase(id);
}

size_t hash_size(unsigned long id) {
    hashtbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end())
        return 0;
    else
        return it->second.size();
}

bool hash_insert(unsigned long id, uint64_t const * seq, size_t size) {
    if (seq == NULL || size == 0)
        return false;

    hashtbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end())
        return false;

    vector<uint64_t> vec(seq, seq + size);
    Sequence s = {vec, id};

    if (it->second.find(s) != it->second.end())
        return false;

    it->second.insert(s);

    return true;
}

bool hash_remove(unsigned long id, uint64_t const * seq, size_t size) {
    if (seq == NULL || size == 0)
        return false;

    hashtbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end())
        return false;

    vector<uint64_t> vec(seq, seq + size);
    Sequence s = {vec, id};

    if (it->second.find(s) == it->second.end())
        return false;

    it->second.erase(s);

    return true;
}

void hash_clear(unsigned long id) {
    hashtbls_t::iterator it = hashTables.find(id);

    if (it != hashTables.end())
        return it->second.clear();
}

bool hash_test(unsigned long id, uint64_t const * seq, size_t size) {
    if (seq == NULL || size == 0)
        return false;

    hashtbls_t::iterator it = hashTables.find(id);

    if (it == hashTables.end())
        return false;

    vector<uint64_t> vec(seq, seq + size);
    Sequence s = {vec, id};

    if (it->second.find(s) == it->second.end())
        return false;
    else
        return true;
}
