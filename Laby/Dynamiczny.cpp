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
    struct node *left, *right;
    ll element, number;
    ll size, height;

    node(ll el, ll num) : left(nullptr), right(nullptr), element(el), number(num), size(num), height(1) {}
};

node *root = nullptr;

ll getLeftSize(node *v) {
    return (v->left ? v->left->size : 0);
}

ll getRightSize(node *v) {
    return (v->right ? v->right->size : 0);
}

ll getLeftHeight(node *v) {
    return (v->left ? v->left->height : 0);
}

ll getRightHeight(node *v) {
    return (v->right ? v->right->height : 0);
}

ll ll_max(ll a, ll b) {
    return a > b ? a : b;
}

ll getHeight(node *v) {
    if (v == nullptr) {
        return 0;
    }
    return ll_max(getLeftHeight(v), getRightHeight(v)) + 1; // byczku
}

ll getSize(node *v) {
    if (v == nullptr) {
        return 0;
    }
    return getLeftSize(v) + getRightSize(v) + v->number;
}

node *rotateRight(node *v) {
    node *vLeft = v->left;
    node *vLeftRight = vLeft->right;

    v->left = vLeftRight;
    vLeft->right = v;

    v->height = getHeight(v);
    vLeft->height = getHeight(vLeft);

    v->size = getSize(v);
    vLeft->size = getSize(vLeft);

    return vLeft;
}

node *rotateLeft(node *v) {
    node *vRight = v->right;
    node *vRightLeft = vRight->left;

    v->right = vRightLeft;
    vRight->left = v;

    v->height = getHeight(v);
    vRight->height = getHeight(vRight);

    v->size = getSize(v);
    vRight->size = getSize(vRight);

    return vRight;
}

node *splay(node *v) {
    if (getLeftHeight(v) - getRightHeight(v) > 1) {
        if (getLeftSize(v->left) > getRightSize(v->left)) {
            v->left = rotateLeft(v->left);
        }

        v = rotateRight(v);
    } else if (getLeftHeight(v) - getRightHeight(v) < -1) {
        if (getLeftSize(v->right) > getRightSize(v->right)) {
            v->right = rotateRight(v->right);
        }

        v = rotateLeft(v);
    }
    return v;
}

node *insert(node *v, ll poz, ll el, ll ile) {
    if (v == nullptr) {
        return new node(el, ile);
    }
    if (poz > getLeftSize(v) + v->number) {
        v->right = insert(v->right, poz - getLeftSize(v) - v->number, el, ile);
        v->size = getSize(v);
        v->height = getHeight(v);

//        return splay(v);
        return v;
    } else if (poz < getLeftSize(v)) {
        v->left = insert(v->left, poz, el, ile);
        v->size = getSize(v);
        v->height = getHeight(v);

//        return splay(v);
        return v;
    }

    node *l = (poz - getLeftSize(v)) > 0 ?
              insert(v->left, getLeftSize(v), v->element, poz - getLeftSize(v)) : v->left;

    node *r = (v->number - poz + getLeftSize(v)) > 0 ?
              insert(v->right, 0, v->element, v->number - poz + getLeftSize(v)) : v->right;

    node *main = new node(el, ile);
    main->left = l;
    main->right = r;

    main->size = getSize(main);
    main->height = getHeight(main);
    return main;
//    return splay(main);
}

ll get(ll poz) {
    node *v = root;

    while (v != nullptr) {
        if (poz >= getLeftSize(v) + v->number) {
            poz -= getLeftSize(v) + v->number;
            v = v->right;
        } else if (poz < getLeftSize(v)) {
            v = v->left;
        } else {
            break;
        }
    }
    return v->element;
}

void test() {
    for (ll i = 0; i < root->size; i++) {
        cout << get(i) << ' ';
    }
    cout << endl;
}

void solve() {
    ll m, a, b, c, lastGet = 0, n = 0;
    cin >> m;
    char o;
    while (m--) {
        cin >> o;
        if (o == 'i') {
            cin >> a >> b >> c;
            a = (a + lastGet) % (n + 1);
            root = insert(root, a, b, c);
        } else {
            cin >> a;
            a = (a + lastGet) % n;
            lastGet = get(a);
            cout << lastGet << endl;
        }
        n = root->size;
    }
}

int main() {
    FASTIO;
//    root = insert(root, 0, 1, 5);
//    test();
//    root = insert(root, 3, 2, 2);
//    test();
//    root = insert(root, 2, 3, 1);
//    test();
//    root = insert(root, 3, 4, 1);
//    test();


    solve();

    return 0;
}