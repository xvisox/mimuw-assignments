#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define endl '\n'
using namespace std;

constexpr int base = 1 << 19;
int tree_up[base << 1], tree_down[base << 1];
set<int> s;
int n, m, ile = 0;

bool add(int v, int t[]) {
    v += base;
    t[v] = 1 - t[v];
    bool result = t[v];
    v /= 2;
    while (v) {
        t[v] = t[2 * v] + t[2 * v + 1];
        v /= 2;
    }
    return result;
}

int query(int a, int b, int t[]) {
    a += base - 1;
    b += base + 1;
    int res = 0;
    while (a / 2 != b / 2) {
        if (a % 2 == 0) {
            res += t[a + 1];
        }
        if (b % 2 == 1) {
            res += t[b - 1];
        }
        a /= 2;
        b /= 2;
    }
    return res;
}

int get_right(set<int>::iterator it) {
    return it == s.end() ? n - 1 : *it;
}

int get_left(set<int>::iterator it) {
    return it == s.begin() ? 0 : *prev(it) + 1;
}

int main() {
    FASTIO;
    cin >> n >> m;
    for (int i = -1; i < n; i++) {
        s.insert(i);
    }
    int ai, op;
    while (m--) {
        cin >> ai >> op;
        if (op == 0) {
            auto node = s.find(ai);

            if (node != s.end()) {
                s.erase(node);

                auto it = s.lower_bound(ai);

                int r = get_right(it);
                int l = get_left(it);

                int up = query(l, r, tree_up);
                int down = query(l, r, tree_down);

                ile += up * down;
            } else {
                auto it = s.lower_bound(ai);

                int r = get_right(it);
                int l = get_left(it);

                int up = query(l, r, tree_up);
                int down = query(l, r, tree_down);

                s.insert(ai);

                ile -= up * down;
            }
        } else {
            bool added = add(ai, op == 1 ? tree_down : tree_up);
            auto it = s.lower_bound(ai);

            int r = get_right(it);
            int l = get_left(it);

            int up = query(l, r, tree_up);
            int down = query(l, r, tree_down);

            if (added) {
                ile += up * down;
            } else {
                ile -= up * down;
            }
        }

        cout << (ile ? "NIE" : "TAK") << endl;
    }

    return 0;
}