#ifndef KVFIFO_H
#define KVFIFO_H

#include <list>
#include <map>
#include <stdexcept>
#include <functional>
#include <memory>
#include <iostream>

template<typename K, typename V>
class kvfifo {
private:
    class kvfifo_implementation {
        using queue_t = std::list<std::pair<K, V>>;
        using queue_it_t = typename queue_t::iterator;
        using list_t = std::list<queue_it_t>;
        using map_t = std::map<K, list_t>;
        using map_it_t = typename map_t::const_iterator;
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

            void drop_rollback() noexcept {
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
                throw std::invalid_argument("kvfifo is empty");
            }
        }

        const list_t &get_list(const K &key) const {
            auto result = it_map.find(key);
            if(result == it_map.end()) {
                throw std::invalid_argument("key not found");
            }

            return std::cref(result->second);
        }

        void throw_if_not_exists(const K &key) const {
            if (it_map.find(key) == it_map.end()) {
                throw std::invalid_argument("key not found");
            }
        }

    public:
        kvfifo_implementation() = default;

        kvfifo_implementation(const kvfifo_implementation &other) {
            // FIXME: What if there is an exception?
            for (auto it = other.fifo.begin(), end = other.fifo.end(); it != end; ++it) {
                push(it->first, it->second);
            }
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
            list_t const &it_list = get_list(key);
            queue_it_t it = it_list.front();
            it_list.pop_front();
            fifo.erase(it);
        }

        void move_to_back(K const &key) {
            // Changing fifo order - keys map will remain the same.
            list_t const &it_list = get_list(key);
            for (auto it: it_list) {
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
            auto list = get_list(key);
            return std::make_pair(std::cref(key), std::ref(list.front()->second));
        }

        std::pair<K const &, V const &> first(K const &key) const {
            auto list = get_list(key);
            return std::make_pair(std::cref(key), std::cref(list.front()->second));
        }

        std::pair<K const &, V &> last(K const &key) {
            auto list = get_list(key);
            return std::make_pair(std::cref(key), std::ref(list.back()->second));
        }

        std::pair<K const &, V const &> last(K const &key) const {
            auto list = get_list(key);
            return std::make_pair(std::cref(key), std::cref(list.back()->second));
        }

        [[nodiscard]] size_t size() const noexcept {
            return fifo.size();
        }

        [[nodiscard]] bool empty() const noexcept {
            return fifo.empty();
        }

        size_t count(K const &key) const {
            return it_map.find(key) == it_map.end() ? 0 : get_list(key).size();
        }

        void clear() noexcept {
            fifo.clear();
            it_map.clear();
        }

        // TODO: remove.
        void print() {
            for (auto &pair: fifo) {
                std::cout << pair.first << " " << pair.second << std::endl;
            }
            std::cout << std::endl;
        }

        class k_iterator : public map_it_t {
            public:
                k_iterator() : map_it_t() {};

                k_iterator(map_it_t it) : map_it_t(it) {};

                K* operator->() { 
                    return (K* const)&(map_it_t::operator->()->first);
                }

                K operator*() {
                    return map_it_t::operator*().first;
                }
        };

        // FIXME: Does it copy it_map?
        // Possible to do it without copying?
        k_iterator k_begin() const noexcept {
            return k_iterator(it_map.begin());
        }

        k_iterator k_end() const noexcept {
            return k_iterator(it_map.end());
        }
    };

    bool should_copy() noexcept {
        return !pimpl.unique() || flag;
    }

    class copy_guard {
    public:
        explicit copy_guard(kvfifo *ptr_kvfifo) : ptr_kvfifo(ptr_kvfifo) {
            old_pimpl = ptr_kvfifo->pimpl;
            old_flag = ptr_kvfifo->flag;

            auto new_pimpl = std::make_shared<kvfifo_implementation>(*(ptr_kvfifo->pimpl));
            ptr_kvfifo->pimpl = new_pimpl;
            ptr_kvfifo->flag = false;

            rollback = true;
        }

        copy_guard(copy_guard const &) = delete;

        copy_guard &operator=(copy_guard const &) = delete;

        copy_guard() = delete;

        ~copy_guard() {
            if (rollback) {
                ptr_kvfifo->pimpl.reset();
                ptr_kvfifo->pimpl = old_pimpl;
                ptr_kvfifo->flag = old_flag;
            }
        }

        void drop_rollback() noexcept {
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
         if(should_copy()) {
            copy_guard guard(this);
            auto result = pimpl->front();
            flag = true;
            guard.drop_rollback();
            return result;
        } else {
            auto result = pimpl->front();
            flag = true;
            return result;
        }
    }

    std::pair<K const &, V const &> front() const {
        return pimpl->front(); // FIXME: right implementation will be executed? I can already tell - no.
    }

    std::pair<K const &, V &> back() {
        if(should_copy()) {
            copy_guard guard(this);
            auto result = pimpl->back();
            flag = true;
            guard.drop_rollback();
            return result;
        } else {
            auto result = pimpl->back();
            flag = true;
            return result;
        }
    }

    std::pair<K const &, V const &> back() const {
        return pimpl->back();
    }

    std::pair<K const &, V &> first(K const &key) {
        if(should_copy()) {
            copy_guard guard(this);
            auto result = pimpl->first(key);
            flag = true;
            guard.drop_rollback();
            return result;
        } else {
            auto result = pimpl->first(key);
            flag = true;
            return result;
        }
    }

    std::pair<K const &, V const &> first(K const &key) const {
        return pimpl->first(key);
    }

    std::pair<K const &, V &> last(K const &key) {
        if(should_copy()) {
            copy_guard guard(this);
            auto result = pimpl->last(key);
            flag = true;
            guard.drop_rollback();
            return result;
        } else {
            auto result = pimpl->last(key);
            flag = true;
            return result;
        }
    }

    std::pair<K const &, V const &> last(K const &key) const {
        return pimpl->last(key);
    }

    [[nodiscard]] size_t size() const noexcept {
        return pimpl->size();
    }

    [[nodiscard]] bool empty() const noexcept {
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

    // TODO: remove.
    void print() {
        pimpl->print();
    }

    using k_iterator = typename kvfifo_implementation::k_iterator;

    k_iterator k_begin() const noexcept {
        return pimpl->k_begin();
    }

    k_iterator k_end() const noexcept {
        return pimpl->k_end();
    }
};

#endif // KVFIFO_H