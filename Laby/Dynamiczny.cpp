#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;

struct node {
    node *left, *right;
    node *parent;
    ll element, number;
    ll size;

    node(ll el, ll num) : left(nullptr), right(nullptr), parent(nullptr), element(el), number(num), size(num) {}
};

node *root = nullptr;

void left_rotate(node *x) {
    node *y = x->right;
    if (y) {
        x->right = y->left;
        if (y->left) y->left->parent = x;
        y->parent = x->parent;

        x->size = x->number;
        if (x->left) x->size += x->left->size;
        if (x->right) x->size += x->right->size;
    }

    if (!x->parent) root = y;
    else if (x == x->parent->left) x->parent->left = y;
    else x->parent->right = y;
    if (y) y->left = x;
    x->parent = y;

    y->size = y->number;
    if (y->left) y->size += y->left->size;
    if (y->right) y->size += y->right->size;
}

void right_rotate(node *x) {
    node *y = x->left;
    if (y) {
        x->left = y->right;
        if (y->right) y->right->parent = x;
        y->parent = x->parent;

        x->size = x->number;
        if (x->left) x->size += x->left->size;
        if (x->right) x->size += x->right->size;
    }
    if (!x->parent) root = y;
    else if (x == x->parent->left) x->parent->left = y;
    else x->parent->right = y;
    if (y) y->right = x;
    x->parent = y;

    y->size = y->number;
    if (y->left) y->size += y->left->size;
    if (y->right) y->size += y->right->size;
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

void insert(ll poz, ll el, ll ile) {
    node *v = root;
    node *p = nullptr;

    bool wasLeft = false;
    while (v != nullptr) {
        if (v->size - v->number < poz && poz < v->size) {
            break;
        } else {
            p = v;
            if (poz >= v->size) {
                poz -= (v->left ? v->left->size : 0) + 1;
                v = v->right;
                wasLeft = false;
            } else {
                v = v->left;
                wasLeft = true;
            }
        }
    }

    if (v) {
        splay(v);
        node *main = new node(el, ile);
        main->left = v->left;
        main->right = v->right;

        if (main->left) main->size += main->left->size;
        if (main->right) main->size += main->right->size;

        root = main;
        insert(v->size - v->number, v->element, poz);
        insert(v->size - v->number + poz + ile, v->element, v->number - poz);

    } else {
        v = new node(el, ile);
        v->parent = p;

        if (!p) root = v;
        else if (!wasLeft) p->right = v;
        else p->left = v;

        if (v->parent) p->size += v->size;

        splay(v);
    }
}

ll getLeftSize(node *v) {
    return (v->left ? v->left->size : 0);
}

ll get(ll poz) {
    poz++;
    node *v = root;
    node *p = nullptr;

    while (v != nullptr) {
        p = v;
        if (getLeftSize(v) < poz && poz <= getLeftSize(v) + v->number) {
            break;
        } else if (poz <= getLeftSize(v)) {
            v = v->left;
        } else {
            poz -= getLeftSize(v) + v->number;
            v = v->right;
        }
    }
    return p->element;
}

void test() {
    for (ll i = 0; i < root->size; i++) {
        cout << get(i) << ' ';
    }
    cout << endl;
}

int main() {
    FASTIO;
//    insert(0, 2, 3); // 2 2 2
//    test();
//    insert(1, 1, 2); // 2 1 1 2 2
//    test();
//    insert(5, 1, 1); // 2 1 1 2 2 1
//    test();
//    insert(3, 3, 2); // 2 1 1 3 3 2 2 1
//    test();

//    insert(0, 1, 1);
//    test();
//    insert(0, 2, 1);
//    test();
//    insert(0, 3, 1);
//    test();
//    insert(0, 4, 1);
//    test();
//    insert(0, 5, 1);
//    test();
//    insert(0, 6, 1);
//    test();

    return 0;
}