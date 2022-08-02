#include <bits/stdc++.h>

#define ll long long

using namespace std;

constexpr int base = 1 << 17;
ll tree[base << 1];

void add(int a, int b, ll value, int k) {
    a = a - 1 + base;
    b = b + 1 + base;
    while (a / 2 != b / 2) {
        if (a % 2 == 0)
            tree[a + 1] = gcd(value * tree[a + 1], k);
        if (b % 2 == 1)
            tree[b - 1] = gcd(value * tree[b - 1], k);
        a /= 2;
        b /= 2;
    }
}

ll query(int a, int k) {
    ll result = 1;
    a = a + base;
    while (a > 0 && result % k != 0) {
        result = gcd(result * tree[a], k);
        a /= 2;
    }
    return result;
}

int main() {
    int n, a, b, c, k;
    char t;
    n = 2 * base;
    for (int i = 0; i < n; i++) tree[i] = 1;
    cin >> n;
    cin >> k;
    for (int i = 0; i < n; i++) {
        cin >> t;
        if (t == 'N') {
            scanf("%d %d %d", &a, &b, &c);
            add(a, b, c, k);
        } else {
            scanf("%d", &a);
            if (query(a, k) % k == 0)
                cout << "TAK\n";
            else
                cout << "NIE\n";

        }
    }
    return 0;
}