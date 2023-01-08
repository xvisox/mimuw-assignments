#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

#include <functional>

#ifndef SPLAY_TREE
#define SPLAY_TREE

class splay_tree {
private:
    unsigned long p_size;

    struct node {
        node *left, *right;
        node *parent;
        int key;
        int max_val, min_val;
        bool connected;

        node(const int &init) {
            left = right = parent = nullptr;
            key = init;
            max_val = min_val = init;
            connected = true;
        }
    } *root;

    int get_max(node *x) {
        return x != nullptr ? x->max_val : INT_MIN;
    }

    int get_min(node *x) {
        return x != nullptr ? x->min_val : INT_MAX;
    }

    bool get_connected(node *x) {
        return x == nullptr || x->connected;
    }

    void update(node *x) {
        if (!x) return;
        x->max_val = max(x->key, max(get_max(x->left), get_max(x->right)));
        x->min_val = min(x->key, min(get_min(x->left), get_min(x->right)));
        x->connected = get_connected(x->left) && get_connected(x->right) &&
                       (x->left == nullptr || (x->key - 1) == get_max(x->left)) &&
                       (x->right == nullptr || (x->key + 1) == get_min(x->right));
    }

    void left_rotate(node *x) {
        node *y = x->right;
        if (y) {
            x->right = y->left;
            if (y->left) y->left->parent = x;
            y->parent = x->parent;
        }

        if (!x->parent) root = y;
        else if (x == x->parent->left) x->parent->left = y;
        else x->parent->right = y;
        if (y) y->left = x;
        x->parent = y;

        update(x);
        update(y);
    }

    void right_rotate(node *x) {
        node *y = x->left;
        if (y) {
            x->left = y->right;
            if (y->right) y->right->parent = x;
            y->parent = x->parent;
        }

        if (!x->parent) root = y;
        else if (x == x->parent->left) x->parent->left = y;
        else x->parent->right = y;
        if (y) y->right = x;
        x->parent = y;

        update(x);
        update(y);
    }

    void splay(node *x) {
        while (x->parent) {
            if (!x->parent->parent) {
                if (x->parent->left == x) right_rotate(x->parent);
                else left_rotate(x->parent);
            } else if (x->parent->left == x && x->parent->parent->left == x->parent) {
                right_rotate(x->parent->parent);
                right_rotate(x->parent);
            } else if (x->parent->right == x && x->parent->parent->right == x->parent) {
                left_rotate(x->parent->parent);
                left_rotate(x->parent);
            } else if (x->parent->left == x && x->parent->parent->right == x->parent) {
                right_rotate(x->parent);
                left_rotate(x->parent);
            } else {
                left_rotate(x->parent);
                right_rotate(x->parent);
            }
        }
    }

public:
    splay_tree() : root(nullptr), p_size(0) {}

    void insert(const int &key) {
        node *z = root;
        node *p = nullptr;

        while (z) {
            p = z;
            if (z->key < key) z = z->right;
            else z = z->left;
        }

        z = new node(key);
        z->parent = p;

        if (!p) root = z;
        else if (p->key < z->key) p->right = z;
        else p->left = z;

        update(p); // ?

        splay(z);
        p_size++;
    }

    node *find(const int &key) {
        node *z = root;
        while (z) {
            if (z->key < key) z = z->right;
            else if (key < z->key) z = z->left;
            else return z;
        }
        return nullptr;
    }

    node *get_root() {
        return root;
    }

    int interval_left(const int &key) {
        splay(find(key));
        assert(root->key == key);
        node *z = root->left;
        int result = key;
        while (z) {
            if (z->max_val != result - 1) break;

            if (z->connected) {
                result = z->min_val;
                break;
            } else if (z->key == result - 1) {
                z = z->left;
                result--;
            } else if (z->right && z->right->connected) {
                result = z->right->min_val;

                if (z->key == result - 1) {
                    z = z->left;
                    result--;
                } else {
                    // tu cud się nie wydarzy
                    break;
                }
            } else {
                z = z->right;
            }
        }
        return result;
    }

    // interval_right analogicznie
    // potem można zaimplementować weight(i)
    // przez 2x split według interval_left(i) i interval_right(i)
    // trzymając w poddrzewie sumę wag węzłów
};

#endif // SPLAY_TREE

constexpr int SIZE = 9;

void check() {
    vector<int> v({1, 2, 3, 11, 12, 13, 21, 22, 23});

    int count = 0;
    while (next_permutation(v.begin(), v.end())) {
        splay_tree tree;
        for (int i = 0; i < SIZE; i++) {
            tree.insert(v[i]);
        }
        auto root = tree.get_root();

        for (int i = 0; i < SIZE; i++) {
            if (v[i] <= 3) {
                assert(tree.interval_left(v[i]) == 1);
            } else if (v[i] <= 13) {
                assert(tree.interval_left(v[i]) == 11);
            } else {
                assert(tree.interval_left(v[i]) == 21);
            }
        }

    }
    cout << count << endl;
}

int main() {
    FASTIO;
    check();
    return 0;
}