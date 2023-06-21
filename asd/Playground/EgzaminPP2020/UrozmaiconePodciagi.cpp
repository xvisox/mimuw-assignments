#include <bits/stdc++.h>

#define ll long long

using namespace std;

constexpr ll MOD = 1e9;
constexpr ll MAX_N = 1e6 + 1;
ll ile[MAX_N], all;
ll n;

int main() {
    cin >> n;
    ll temp, tmp;

    scanf("%lld", &temp);
    all++;
    ile[temp]++;

    for (int i = 1; i < n; i++) {
        scanf("%lld", &temp);
        tmp = all - ile[temp];

        all = (all + tmp + 1) % MOD;
        if (all < 0) all += MOD;
        ile[temp] = (ile[temp] + tmp + 1) % MOD;
        if (ile[temp] < 0) ile[temp] += MOD;
    }

    cout << (all % MOD) << endl;
    return 0;
}