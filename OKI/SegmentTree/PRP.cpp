#include <bits/stdc++.h>

#define ll long long

using namespace std;

constexpr int base = 1 << 17;
constexpr int modulo = 1e9 + 7;
ll tree[base << 1];

void add(int a, int b, ll value) {
    a = a - 1 + base;
    b = b + 1 + base;
    while (a / 2 != b / 2) {
        if (a % 2 == 0)
            tree[a + 1] = (value * tree[a + 1]) % modulo;
        if (b % 2 == 1)
            tree[b - 1] = (value * tree[b - 1]) % modulo;
        a /= 2;
        b /= 2;
    }
}

ll query(int a) {
    ll result = 1;
    a = a + base;
    while (a > 0) {
        result = (result * tree[a]) % modulo;
        a /= 2;
    }
    return result;
}

int main() {
    int n, t, a, b, c;
    n = 2 * base;
    for (int i = 0; i < n; i++) tree[i] = 1;
    cin >> n;
    for (int i = 0; i < n; i++) {
        cin >> t;
        if (t == 0) {
            scanf("%d %d %d", &a, &b, &c);
            add(a, b, c);
        } else {
            scanf("%d", &a);
            cout << query(a) << '\n';
        }
    }
    return 0;
}