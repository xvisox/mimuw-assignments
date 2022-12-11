#ifndef KVFIFO_H
#define KVFIFO_H

#include <bits/stdc++.h> // TODO: change to more specific headers

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

    class pushFifoGuard {
    public:
        pushFifoGuard(std::shared_ptr<queue_t> fifo, const K &key, const V &value) : fifo(fifo) {
            fifo->push_back({key, value});
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
        return !fifo.unique() > 1 || !keys.unique() > 1 || flag;
    }

    void copy_kvfifo() {
        if (!shouldCopy()) return;

        kvfifo<K, V> newFifo;
        for (auto &pair: *fifo) {
            newFifo.push(pair.first, pair.second);
        }
        // newFifo has flag set to false, so it won't copy itself again
        *this = newFifo;
    }

public:
    kvfifo() : fifo(std::make_shared<queue_t>()), keys(std::make_shared<map_t>()), flag(false) {}

    kvfifo(const kvfifo &other) : fifo(other.fifo), keys(other.keys), flag(other.flag) {
        copy_kvfifo();
    }

    kvfifo(kvfifo &&other) noexcept: fifo(std::move(other.fifo)), keys(std::move(other.keys)), flag(other.flag) {}

    kvfifo &operator=(kvfifo other) {
        fifo = other.fifo;
        keys = other.keys;
        flag = other.flag;
        return *this;
    }

    void push(K const &k, V const &v) {
        copy_kvfifo();

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

        copy_kvfifo();

        queue_it_t it = fifo->begin();
        keys->find(it->first)->second.pop_front();
        fifo->pop_front();
    }

    void pop(K const &key) {
        throwIfEmpty();

        copy_kvfifo();

        queue_it_t it = keys->find(key)->second.front();
        keys->find(key)->second.pop_front();
        fifo->erase(it);
    }

    void move_to_back(K const &k) {
        if (keys->find(k) == keys->end()) {
            throw std::invalid_argument("move_to_back() called on non-existing key");
        }

        copy_kvfifo();

        // Changing fifo order - keys map will remain the same.
        for (queue_it_t it: keys->find(k)->second) {
            fifo->splice(fifo->end(), *fifo, it);
        }
    }

    std::pair<const K &, V &> front() {
        throwIfEmpty();

        copy_kvfifo();

        flag = true;
        return std::make_pair(std::cref(fifo->front().first), std::ref(fifo->front().second));
    }

    std::pair<K const &, V const &> front() const {
        throwIfEmpty();

        return std::make_pair(std::cref(fifo->front().first), std::cref(fifo->front().second));
    }

    std::pair<K const &, V &> back() {
        throwIfEmpty();

        copy_kvfifo();

        flag = true;
        return std::make_pair(std::cref(fifo->front().first), std::ref(fifo->front().second));
    }

    std::pair<K const &, V const &> back() const {
        throwIfEmpty();

        return std::make_pair(std::cref(fifo->front().first), std::cref(fifo->front().second));
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
        copy_kvfifo();
        fifo->clear();
        keys->clear();
    }

};

#endif // KVFIFO_H