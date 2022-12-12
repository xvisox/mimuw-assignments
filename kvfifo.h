#ifndef KVFIFO_H
#define KVFIFO_H

#include <bits/stdc++.h> // TODO: zmienić na konkretniejsze nagłówki.

template<typename K, typename V>
class kvfifo {
    using queue_t = std::list<std::pair<K, V>>;
    using queue_it_t = typename queue_t::iterator;
    using map_t = std::map<K, std::list<queue_it_t>>;
private:
    std::shared_ptr<queue_t> fifo;
    std::shared_ptr<map_t> keys;
    bool flag;

    void throwIfEmpty() const {
        if (fifo->empty())
            throw std::invalid_argument("kvfifo is empty");
    }

    void throwIfNotExists(const K &key) const {
        if (keys->find(key) == keys->end())
            throw std::invalid_argument("key does not exist");
    }

    class pushFifoGuard {
    public:
        pushFifoGuard(std::shared_ptr<queue_t> fifo, const K &key, const V &value) : fifo(fifo) {
            fifo->push_back(std::make_pair(key, value));
            rollback = true;
        }

        ~pushFifoGuard() {
            if (rollback) {
                fifo->pop_back();
            }
        }

        void dropRollback() {
            rollback = false;
        }

        pushFifoGuard(pushFifoGuard const &) = delete;

        pushFifoGuard &operator=(pushFifoGuard const &) = delete;

    private:
        std::shared_ptr<queue_t> fifo;
        bool rollback = false;
    };

    [[nodiscard]] bool shouldCopy() const {
        return !fifo.unique() || !keys.unique() || flag;
    }

    void copy_kvfifo(bool copy) {
        if (!copy) return;

        kvfifo<K, V> newFifo;
        for (auto &pair: *fifo) {
            newFifo.push(pair.first, pair.second);
        }
        *this = std::move(newFifo);
    }

public:
    kvfifo() : fifo(std::make_shared<queue_t>()), keys(std::make_shared<map_t>()), flag(false) {}

    kvfifo(const kvfifo &other) : fifo(other.fifo), keys(other.keys), flag(other.flag) {
        copy_kvfifo(flag);
    }

    kvfifo(kvfifo &&other) noexcept: fifo(std::move(other.fifo)), keys(std::move(other.keys)), flag(other.flag) {}

    kvfifo &operator=(kvfifo other) {
        fifo = other.fifo;
        keys = other.keys;
        flag = other.flag;
        return *this;
    }

    void push(K const &k, V const &v) {
        copy_kvfifo(shouldCopy());

        pushFifoGuard guard(fifo, k, v);
        queue_it_t last = std::prev(fifo->end());

        if (keys->find(k) != keys->end()) {
            keys->find(k)->second.push_back(last);
        } else {
            // FIXME: Czy lista się usunie, jeśli insert się nie powiedzie?
            keys->insert(std::make_pair(k, std::list<queue_it_t>{last}));
        }

        guard.dropRollback();
    }

    void pop() {
        throwIfEmpty();

        copy_kvfifo(shouldCopy());

        queue_it_t it = fifo->begin();
        keys->find(it->first)->second.pop_front();
        fifo->pop_front();
    }

    void pop(K const &key) {
        throwIfEmpty();

        copy_kvfifo(shouldCopy());

        queue_it_t it = keys->find(key)->second.front();
        keys->find(key)->second.pop_front();
        fifo->erase(it);
    }

    void move_to_back(K const &k) {
        throwIfNotExists(k);

        copy_kvfifo(shouldCopy());

        // Changing fifo order - keys map will remain the same.
        for (queue_it_t it: keys->find(k)->second) {
            fifo->splice(fifo->end(), *fifo, it);
        }
    }

    std::pair<const K &, V &> front() {
        throwIfEmpty();

        copy_kvfifo(shouldCopy());

        flag = true;
        return std::make_pair(std::cref(fifo->front().first), std::ref(fifo->front().second));
    }

    std::pair<K const &, V const &> front() const {
        throwIfEmpty();

        return std::make_pair(std::cref(fifo->front().first), std::cref(fifo->front().second));
    }

    std::pair<K const &, V &> back() {
        throwIfEmpty();

        copy_kvfifo(shouldCopy());

        flag = true;
        return std::make_pair(std::cref(fifo->front().first), std::ref(fifo->back().second));
    }

    std::pair<K const &, V const &> back() const {
        throwIfEmpty();

        return std::make_pair(std::cref(fifo->front().first), std::cref(fifo->back().second));
    }

    std::pair<K const &, V &> first(K const &key) {
        throwIfNotExists(key);

        copy_kvfifo(shouldCopy());

        flag = true;
        // TODO: Nie wiem, czy cref(key) jest poprawne albo czy nie powinno być po prostu key.
        return std::make_pair(std::cref(key), std::ref(keys->find(key)->second.front()->second));
    }

    std::pair<K const &, V const &> first(K const &key) const {
        throwIfNotExists(key);

        return std::make_pair(std::cref(key), std::cref(keys->find(key)->second.front()->second));
    }

    std::pair<K const &, V &> last(K const &key) {
        throwIfNotExists(key);

        copy_kvfifo(shouldCopy());

        flag = true;
        return std::make_pair(std::cref(key), std::ref(keys->find(key)->second.back()->second));
    }

    std::pair<K const &, V const &> last(K const &key) const {
        throwIfNotExists(key);

        return std::make_pair(std::cref(key), std::cref(keys->find(key)->second.back()->second));
    }

    [[nodiscard]] size_t size() const {
        return fifo->size();
    }

    [[nodiscard]] bool empty() const {
        return fifo->empty();
    }

    size_t count(K const &k) const {
        if (keys->find(k) == keys->end()) {
            return 0;
        } else {
            return keys->find(k)->second.size();
        }
    }

    void clear() {
        copy_kvfifo(shouldCopy());
        fifo->clear();
        keys->clear();
    }

    // TODO: usunąć
    void print() {
        for (auto &pair: *fifo) {
            std::cout << pair.first << " " << pair.second << std::endl;
        }
        std::cout << std::endl;
    }

};

#endif // KVFIFO_H