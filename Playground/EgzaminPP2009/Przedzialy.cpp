#include <bits/stdc++.h>

#define ll long long

using namespace std;

ll n;
vector<pair<ll, ll>> input;

void read() {
    cin >> n;
    ll ai, bi;
    for (int i = 0; i < n; i++) {
        scanf("%lld %lld", &ai, &bi);
        input.emplace_back(ai, bi);
    }
    sort(input.begin(), input.end());
}

ll ll_min(ll a, ll b) {
    return a < b ? a : b;
}

void solve() {
    ll lastL, lastP;
    lastL = input[0].first;
    lastP = input[0].second;

    ll res = INT_MAX;
    for (int i = 1; i < n && res; i++) {
        auto [currL, currP] = input[i];
        if (currL <= lastP) res = 0;
        else {
            res = ll_min(res, currL - lastP);
        }

        lastL = currL;
        lastP = currP;
    }

    cout << res << endl;
}

int main() {
    read();
    solve();
    return 0;
}