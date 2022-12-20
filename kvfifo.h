#ifndef KVFIFO_H
#define KVFIFO_H

#include <list>
#include <map>
#include <stdexcept>
#include <functional>
#include <memory>
#include <iostream> // usunac

template<typename K, typename V>
class kvfifo {
private:
    class kvfifo_implementation {
        using queue_t = std::list<std::pair<K, V>>; // TODO: tylko wartosci
        using queue_it_t = typename queue_t::iterator;
        using list_t = std::list<queue_it_t>;
        using map_t = std::map<K, list_t>;
    private:
        queue_t fifo;
        map_t it_map;
        bool copy_flag = false; // True if non-const reference was taken - need to copy on every modification from now on.

        void throw_if_empty() const {
            if (fifo.empty()) {
                throw std::invalid_argument("kvfifo is empty");
            }
        }

        void throw_if_not_exists(const K &key) const {
            if (it_map.find(key) == it_map.end()) {
                throw std::invalid_argument("key not found");
            }
        }

        list_t &get_list(const K &key) {
            auto result = it_map.find(key);
            if(result == it_map.end()) {
                throw std::invalid_argument("key not found");
            }

            return std::ref(result->second);
        }

        const list_t &get_list(const K &key) const {
            auto result = it_map.find(key);
            if(result == it_map.end()) {
                throw std::invalid_argument("key not found");
            }

            return std::cref(result->second);
        }

        std::pair<const K&, V&> make_ref_pair(const K &k, V &v) {
            throw_if_empty();
            return std::make_pair(std::cref(k), std::ref(v));
        }

        std::pair<const K&, const V&> make_ref_pair(const K &k, const V &v) const {
            throw_if_empty();
            return std::make_pair(std::cref(k), std::cref(v));
        }

    public:
        kvfifo_implementation() = default;

        kvfifo_implementation(const kvfifo_implementation &other) {
            // FIXME: What if there is an exception?
            for (auto it = other.fifo.begin(), end = other.fifo.end(); it != end; ++it) {
                push(it->first, it->second);
            }
        }

        kvfifo_implementation(kvfifo_implementation &&other) noexcept : 
            fifo(std::move(other.fifo)), it_map(std::move(other.it_map)) {}

        kvfifo_implementation &operator=(kvfifo_implementation other) {
            fifo = other.fifo;
            it_map = other.it_map;
            // TODO: I think we should NOT copy copy_flag, this is a whole new implemtantion, right?
            return *this;
        }

        void push(K const &k, V const &v) {
            auto it_list = it_map.find(k);

            if (it_list != it_map.end()) {
                queue_t queue_addition{std::make_pair(k, v)};
                queue_it_t list_record = queue_addition.begin();

                it_list->second.push_back(list_record);
                fifo.splice(fifo.end(), queue_addition, queue_addition.begin());
            } else {
                queue_t queue_addition{std::make_pair(k, v)};
                queue_it_t list_record = queue_addition.begin();
                list_t list{list_record};
                auto map_record = std::make_pair(k, list);

                it_map.insert(map_record);
                fifo.splice(fifo.end(), queue_addition, queue_addition.begin());
            }
        }

        void pop() {
            throw_if_empty();

            queue_it_t it = fifo.begin();
            it_map.find(it->first)->second.pop_front();
            fifo.pop_front();
        }

        void pop(K const &key) {
            list_t &it_list = get_list(key);
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
            return make_ref_pair(fifo.front().first, fifo.front().second);
        }

        std::pair<K const &, V const &> front() const {
            return make_ref_pair(fifo.front().first, fifo.front().second);
        }

        std::pair<const K &, V &> back() {
            return make_ref_pair(fifo.back().first, fifo.back().second);
        }

        std::pair<K const &, V const &> back() const {
            return make_ref_pair(fifo.back().first, fifo.back().second);
        }

        std::pair<K const &, V &> first(K const &key) {
            auto list = get_list(key);
            return make_ref_pair(key, list.front()->second);
        }

        std::pair<K const &, V const &> first(K const &key) const {
            auto list = get_list(key);
            return make_ref_pair(key, list.front()->second);
        }

        std::pair<K const &, V &> last(K const &key) {
            auto list = get_list(key);
            return make_ref_pair(key, list.back()->second);
        }

        std::pair<K const &, V const &> last(K const &key) const {
            auto list = get_list(key);
            return make_ref_pair(key, list.back()->second);
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
            // TODO: Should we set flag to false?
            copy_flag = false;
        }

        bool flag() const noexcept {
            return copy_flag;
        }

        void set_flag() noexcept {
            copy_flag = true;
        }

        // TODO: remove.
        void print() {
            for (auto &pair: fifo) {
                std::cout << pair.first << " " << pair.second << std::endl;
            }
            std::cout << std::endl;
        }

        class k_iterator : public std::iterator<std::bidirectional_iterator_tag, K> {
            public:
                using map_it_t = typename map_t::const_iterator;

                k_iterator() : it() {};

                k_iterator(map_it_t other) : it(other) {};

                const K &operator*() const {
                    return it->first;
                }

                k_iterator &operator++() noexcept {
                    ++it;
                    return *this; 
                }

                k_iterator operator++(int) noexcept {
                    k_iterator temp(*this);
                    ++(*this);
                    return temp;
                }
                
                k_iterator &operator--() noexcept {
                    --it;
                    return *this; 
                }

                k_iterator operator--(int) noexcept {
                    k_iterator temp(*this);
                    --(*this);
                    return temp;
                }

                bool operator==(const k_iterator &other) const noexcept {
                    return it == other.it;
                }

                bool operator!=(const k_iterator &other) const noexcept {
                    return it != other.it;
                }

            private:
                map_it_t it;
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
        return !pimpl.unique() || pimpl->flag();
    }

    class copy_guard {
    public:
        explicit copy_guard(kvfifo *ptr_kvfifo) : ptr_kvfifo(ptr_kvfifo) {
            old_pimpl = ptr_kvfifo->pimpl;

            auto new_pimpl = std::make_shared<kvfifo_implementation>(*(ptr_kvfifo->pimpl));
            ptr_kvfifo->pimpl = new_pimpl;

            rollback = true;
        }

        copy_guard(copy_guard const &) = delete;

        copy_guard &operator=(copy_guard const &) = delete;

        copy_guard() = delete;

        ~copy_guard() {
            if (rollback) {
                ptr_kvfifo->pimpl.reset();
                ptr_kvfifo->pimpl = old_pimpl;
            }
        }

        void drop_rollback() noexcept {
            rollback = false;
        }

    private:
        kvfifo *ptr_kvfifo;
        std::shared_ptr<kvfifo_implementation> old_pimpl;
        bool rollback = false;
    };

    std::shared_ptr<kvfifo_implementation> pimpl;
public:
    kvfifo() : pimpl(std::make_shared<kvfifo_implementation>()) {}

    kvfifo(kvfifo const &other) {
        if(other.pimpl->flag()) {
            auto new_pimpl = std::make_shared<kvfifo_implementation>(*(other.pimpl));
            pimpl = new_pimpl;
        } else {
            pimpl = other.pimpl;
        }
    }

    kvfifo(kvfifo &&other) noexcept: pimpl(std::move(other.pimpl)) {
        // FIXME: copy here?
    }

    kvfifo &operator=(kvfifo other) {
        pimpl = other.pimpl;
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

    // TODO: Repeated code in guards
    std::pair<K const &, V &> front() {
         if(should_copy()) {
            copy_guard guard(this);
            auto result = pimpl->front();
            pimpl->set_flag();
            guard.drop_rollback();
            return result;
        } else {
            auto result = pimpl->front();
            pimpl->set_flag();
            return result;
        }
    }

    std::pair<K const &, V const &> front() const {
        return pimpl->front(); 
        // FIXME: right implementation will be executed? I can already tell - no.
        // It's probably ok
    }

    std::pair<K const &, V &> back() {
        if(should_copy()) {
            copy_guard guard(this);
            auto result = pimpl->back();
            pimpl->set_flag();
            guard.drop_rollback();
            return result;
        } else {
            auto result = pimpl->back();
            pimpl->set_flag();
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
            pimpl->set_flag();
            guard.drop_rollback();
            return result;
        } else {
            auto result = pimpl->first(key);
            pimpl->set_flag();
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
            pimpl->set_flag();
            guard.drop_rollback();
            return result;
        } else {
            auto result = pimpl->last(key);
            pimpl->set_flag();
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