#include <bits/stdc++.h>

#define ll long long

using namespace std;

int main() {
    int t;
    cin >> t;
    ll n, a, b;
    for (int i = 0; i < t; i++) {
        scanf("%lld %lld %lld", &n, &a, &b);
        if (a == 1) {
            if ((n - 1) % b == 0) cout << "Yes\n";
            else cout << "No\n";
            continue;
        }

        ll k = 1;
        bool is = false;
        while (k <= n && !is) {
            if (n % b == k % b) {
                is = true;
            }
            k *= a;
        }
        cout << (is ? "Yes\n" : "No\n");
    }

    return 0;
}