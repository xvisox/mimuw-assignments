#include <bits/stdc++.h>

using namespace std;

constexpr int base = 1 << 17;
int tree[base << 1];

void add(int v, int value) {
    v = v + base;
    tree[v] = value;
    v = v >> 1;
    while (v > 0) {
        tree[v] = max(tree[(v << 1)], tree[(v << 1) + 1]);
        v = v >> 1;
    }
}

int query(int a, int b) {
    int result = 0;
    a = a - 1 + base;
    b = b + 1 + base;
    while (a / 2 != b / 2) {
        if (a % 2 == 0) result = max(tree[a + 1], result);
        if (b % 2 == 1) result = max(tree[b - 1], result);
        a /= 2;
        b /= 2;
    }
    return result;
}

int main() {
    int n, t, a, b;
    scanf("%d", &n);
    for (int i = 0; i < n; i++) {
        scanf("%d %d %d", &t, &a, &b);
        if (t == 0) {
            add(a, b);
        } else {
            cout << query(a, b) << '\n';
        }
    }

    return 0;
}