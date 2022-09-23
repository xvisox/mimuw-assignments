#include <bits/stdc++.h>

#define INF (INT_MAX)
#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)

constexpr int MAX_N = (2 * 1e5) + 10;
using namespace std;
int t, n;
int tab[MAX_N];

vector<pair<int, int>> adj[MAX_N]; // {adj, weight}
int dst[MAX_N];
bitset<MAX_N> visited;
priority_queue<pair<int, int>> q;

void read() {
    cin >> n;
    for (int j = 0; j < n; j++) {
        cin >> tab[j];
    }
}

void solve() {
    visited.reset();
    for (int i = 0; i < n; i++) {
        adj[i].clear();
        adj[i].emplace_back(i + 2, tab[i]); // friend kills first
        adj[i].emplace_back(i + 3, tab[i]); // friend kills first and I kill next two
        adj[i].emplace_back(i + 3, tab[i] + tab[i + 1]); // friend kills first and second
        adj[i].emplace_back(i + 4, tab[i] + tab[i + 1]); // friend and I kill both monsters
        dst[i] = INF;
    }
    for (int i = n; i <= n + 4; i++) {
        dst[i] = INF;
    }

    q.push({0, 0});
    dst[0] = 0;
    while (!q.empty()) {
        auto [distance, v] = q.top();
        q.pop();
        if (visited[v]) continue;
        visited[v] = true;

        for (auto [u, weight]: adj[v]) {
            if (dst[v] + weight < dst[u]) {
                dst[u] = dst[v] + weight;
                q.push({-dst[u], u});
            }
        }
    }
    cout << min({dst[n], dst[n + 1], dst[n + 2], dst[n + 3]}) << '\n';
}

int main() {
    FASTIO;
    cin >> t;
    for (int i = 0; i < t; i++) {
        read();
        solve();
    }
    return 0;
}
