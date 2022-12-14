#ifndef KVFIFO_H
#define KVFIFO_H

#include <bits/stdc++.h> // TODO: zmienić na konkretniejsze nagłówki.

template<typename K, typename V>
class kvfifo {
private:
    class kvfifo_implementation {
        using queue_t = std::list<std::pair<K, V>>;
        using queue_it_t = typename queue_t::iterator;
        using list_t = std::list<queue_it_t>;
        using list_it_t = typename list_t::iterator;
        using map_t = std::map<K, list_t>;
        using map_it_t = typename map_t::iterator;
    private:
        queue_t fifo;
        map_t it_map;

        class push_fifo_guard {
        public:
            push_fifo_guard(queue_t *ptr_fifo, const K &key, const V &value) : ptr_fifo(ptr_fifo) {
                ptr_fifo->push_back(std::make_pair(key, value));
                rollback = true;
            }

            ~push_fifo_guard() {
                if (rollback) {
                    ptr_fifo->pop_back();
                }
            }

            void drop_rollback() {
                rollback = false;
            }

            push_fifo_guard(push_fifo_guard const &) = delete;

            push_fifo_guard &operator=(push_fifo_guard const &) = delete;

        private:
            queue_t *ptr_fifo;
            bool rollback = false;
        };

        void throw_if_empty() const {
            if (fifo.empty()) {
                throw std::out_of_range("kvfifo is empty");
            }
        }

        void throw_if_not_exists(const K &key) const {
            if (it_map.find(key) == it_map.end()) {
                throw std::out_of_range("key not found");
            }
        }

        const list_t &get_list(const K &key) const {
            throw_if_not_exists(key);
            return it_map.find(key)->second;
        }

    public:
        kvfifo_implementation() = default;

        kvfifo_implementation(const kvfifo_implementation &other) {
            kvfifo_implementation new_fifo;
            for (auto &pair: other.fifo) {
                new_fifo.push(pair.first, pair.second);
            }
            *this = std::move(new_fifo);
        }

        kvfifo_implementation(kvfifo_implementation &&other)
        noexcept: fifo(std::move(other.fifo)), it_map(std::move(other.it_map)) {}

        kvfifo_implementation &operator=(kvfifo_implementation other) {
            fifo = other.fifo;
            it_map = other.it_map;
            return *this;
        }

        void push(K const &k, V const &v) {
            push_fifo_guard guard(&fifo, k, v);
            queue_it_t last = std::prev(fifo.end());

            auto it_list = it_map.find(k);

            if (it_list != it_map.end()) {
                it_list->second.push_back(last);
            } else {
                list_t list{last};
                std::pair<K, list_t> it_map_record(k, list);
                it_map.insert(it_map_record);
            }

            guard.drop_rollback();
        }

        void pop() {
            throw_if_empty();

            queue_it_t it = fifo.begin();
            it_map.find(it->first)->second.pop_front();
            fifo.pop_front();
        }

        void pop(K const &key) {
            throw_if_not_exists(key);

            auto it_list = get_list(key);
            queue_it_t it = it_list.front();
            it_list.pop_front();
            fifo.erase(it);
        }

        void move_to_back(K const &key) {
            throw_if_not_exists(key);

            // Changing fifo order - keys map will remain the same.
            auto it_list = get_list(key);
            for (queue_it_t it: it_list) {
                fifo.splice(fifo.end(), fifo, it);
            }
        }

        std::pair<const K &, V &> front() {
            throw_if_empty();
            return std::make_pair(std::cref(fifo.front().first), std::ref(fifo.front().second));
        }

        std::pair<K const &, V const &> front() const {
            throw_if_empty();
            return std::make_pair(std::cref(fifo.front().first), std::cref(fifo.front().second));
        }

        std::pair<const K &, V &> back() {
            throw_if_empty();
            return std::make_pair(std::cref(fifo.back().first), std::ref(fifo.back().second));
        }

        std::pair<K const &, V const &> back() const {
            throw_if_empty();
            return std::make_pair(std::cref(fifo.back().first), std::cref(fifo.back().second));
        }

        std::pair<K const &, V &> first(K const &key) {
            throw_if_not_exists(key);
            return std::make_pair(std::cref(key), std::ref(get_list(key).front()->second));
        }

        std::pair<K const &, V const &> first(K const &key) const {
            throw_if_not_exists(key);
            return std::make_pair(std::cref(key), std::cref(get_list(key).front()->second));
        }

        std::pair<K const &, V &> last(K const &key) {
            throw_if_not_exists(key);
            return std::make_pair(std::cref(key), std::ref(get_list(key).back()->second));
        }

        std::pair<K const &, V const &> last(K const &key) const {
            throw_if_not_exists(key);
            return std::make_pair(std::cref(key), std::cref(get_list(key).back()->second));
        }

        [[nodiscard]] size_t size() const {
            return fifo.size();
        }

        [[nodiscard]] bool empty() const {
            return fifo.empty();
        }

        size_t count(K const &key) const {
            return it_map.find(key) == it_map.end() ? 0 : get_list(key).size();
        }

        void clear() {
            fifo.clear();
            it_map.clear();
        }
    };

    bool should_copy() {
        return !pimpl.unique() || flag;
    }

    class copy_guard {
    public:
        explicit copy_guard(kvfifo *ptr_kvfifo) : ptr_kvfifo(ptr_kvfifo) {
            // FIXME: copy constructor should execute here.
            kvfifo_implementation new_kvfifo(*(ptr_kvfifo->pimpl));
            old_pimpl = ptr_kvfifo->pimpl;
            old_flag = ptr_kvfifo->flag;

            try {
                auto new_pimpl = std::make_shared<kvfifo_implementation>(new_kvfifo);
                ptr_kvfifo->pimpl = new_pimpl;
                ptr_kvfifo->flag = false;
            } catch (...) {
                new_kvfifo.clear();
                throw;
            }

            rollback = true;
        }

        ~copy_guard() {
            if (rollback) {
                ptr_kvfifo->pimpl->clear();

                ptr_kvfifo->pimpl = old_pimpl;
                ptr_kvfifo->flag = old_flag;
            }
        }

        void drop_rollback() {
            rollback = false;
        }

    private:
        kvfifo *ptr_kvfifo;
        std::shared_ptr<kvfifo_implementation> old_pimpl;
        bool old_flag;
        bool rollback = false;
    };

    std::shared_ptr<kvfifo_implementation> pimpl;
    bool flag;
public:
    kvfifo() : pimpl(std::make_shared<kvfifo_implementation>()), flag(false) {}

    kvfifo(kvfifo const &kvfifo) : pimpl(kvfifo.pimpl), flag(kvfifo.flag) {
        if (!flag) return;

        copy_guard guard(this);
        guard.drop_rollback();
    }

    kvfifo(kvfifo &&kvfifo) noexcept: pimpl(std::move(kvfifo.pimpl)), flag(kvfifo.flag) {
        // FIXME: copy here?
    }

    kvfifo &operator=(kvfifo other) {
        pimpl = other.pimpl;
        flag = other.flag;
        return *this;
    }

    void push(K const &k, V const &v) {
        if (should_copy()) {
            copy_guard guard(this);
            pimpl->push(k, v);
            guard.drop_rollback();
        } else {
            pimpl->push(k, v);
        }
    }

    void pop() {
        if (should_copy()) {
            copy_guard guard(this);
            pimpl->pop();
            guard.drop_rollback();
        } else {
            pimpl->pop();
        }
    }

    void pop(K const &key) {
        if (should_copy()) {
            copy_guard guard(this);
            pimpl->pop(key);
            guard.drop_rollback();
        } else {
            pimpl->pop(key);
        }
    }

    void move_to_back(K const &key) {
        if (should_copy()) {
            copy_guard guard(this);
            pimpl->move_to_back(key);
            guard.drop_rollback();
        } else {
            pimpl->move_to_back(key);
        }
    }

    std::pair<K const &, V &> front() {
        if (should_copy()) {
            copy_guard guard(this);
            guard.drop_rollback();
        }
        flag = true;
        return pimpl->front();
    }

    std::pair<K const &, V const &> front() const {
        return pimpl->front(); // FIXME: right implementation will be executed?
    }

    std::pair<K const &, V &> back() {
        if (should_copy()) {
            copy_guard guard(this);
            guard.drop_rollback();
        }
        flag = true;
        return pimpl->back();
    }

    std::pair<K const &, V const &> back() const {
        return pimpl->back();
    }

    std::pair<K const &, V &> first(K const &key) {
        if (should_copy()) {
            copy_guard guard(this);
            guard.drop_rollback();
        }
        flag = true;
        return pimpl->first(key);
    }

    std::pair<K const &, V const &> first(K const &key) const {
        return pimpl->first(key);
    }

    std::pair<K const &, V &> last(K const &key) {
        if (should_copy()) {
            copy_guard guard(this);
            guard.drop_rollback();
        }
        flag = true;
        return pimpl->last(key);
    }

    std::pair<K const &, V const &> last(K const &key) const {
        return pimpl->last(key);
    }

    [[nodiscard]] size_t size() const {
        return pimpl->size();
    }

    [[nodiscard]] bool empty() const {
        return pimpl->empty();
    }

    size_t count(K const &key) const {
        return pimpl->count(key);
    }

    void clear() {
        if (should_copy()) {
            copy_guard guard(this);
            pimpl->clear();
            guard.drop_rollback();
        } else {
            pimpl->clear();
        }
    }

    // TODO: iterator

};

#endif // KVFIFO_H