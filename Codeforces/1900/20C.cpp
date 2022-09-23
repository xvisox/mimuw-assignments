#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
using namespace std;
int n, m;
constexpr int MAX_N = 1e5 + 1;
vector<pair<ll, ll>> adj[MAX_N];
ll dst[MAX_N], last[MAX_N];
bitset<MAX_N> processed;

void read() {
    FASTIO;
    cin >> n >> m;
    int ai, bi, wi;
    for (int i = 0; i < m; i++) {
        cin >> ai >> bi >> wi;
        adj[ai].emplace_back(bi, wi);
        adj[bi].emplace_back(ai, wi);
    }
    fill_n(&dst[1], n, LLONG_MAX);
}

void solve() {
    priority_queue<pair<ll, ll>> q;
    dst[1] = 0;
    last[1] = 1;
    q.push({0, 1});

    while (!q.empty() && !processed[n]) {
        auto [temp, v] = q.top();
        q.pop();
        if (processed[v]) continue;
        processed[v] = true;

        for (auto [u, weight]: adj[v]) {
            if (dst[v] + weight < dst[u]) {
                dst[u] = weight + dst[v];
                last[u] = v;
                q.push({-dst[u], u});
            }
        }
        adj[v].clear();
    }
    if (dst[n] == LLONG_MAX) {
        cout << -1 << '\n';
    } else {
        ll x = n;
        vector<ll> odp;
        while (x != 1) {
            odp.push_back(x);
            x = last[x];
        }
        odp.push_back(1);
        for (auto it = odp.rbegin(); it != odp.rend(); ++it) {
            cout << *it << ' ';
        }
        cout << '\n';
    }
}

int main() {
    read();
    solve();

    return 0;
}