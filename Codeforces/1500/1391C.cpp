#include <bits/stdc++.h>

#define ll long long

using namespace std;
constexpr ll MOD = 1e9 + 7;

ll modFact(ll n, ll p) {
    if (n >= p)
        return 0;

    ll result = 1;
    for (ll i = 1; i <= n; i++)
        result = (result * i) % p;

    return result;
}

ll modPow(ll n) {
    if (n == 0) return 1;

    ll y = 1;
    ll x = 2;
    while (n > 1) {
        if (n % 2 == 0) {
            x = (x * x) % MOD;
            n /= 2;
        } else {
            y = (y * x) % MOD;
            x = (x * x) % MOD;
            n = (n - 1) / 2;
        }
    }
    return (x * y) % MOD;
}

int main() {
    ll n;
    cin >> n; // n! - 2^(n-1)
    ll result = modFact(n, MOD) - modPow(n - 1);
    while (result < 0) {
        result += MOD;
    }
    cout << result << endl;

    return 0;
}