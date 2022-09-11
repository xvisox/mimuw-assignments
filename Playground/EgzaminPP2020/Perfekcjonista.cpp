#include <bits/stdc++.h>

#define MAX_N 100001

using namespace std;

int n, m;
vector<pair<int, int>> adj[MAX_N];
int dst[MAX_N], previous[MAX_N];
bool processed[MAX_N];

void read() {
    cin >> n >> m;
    int ai, bi, wi;
    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &ai, &bi, &wi);
        adj[ai].emplace_back(bi, wi);
        adj[bi].emplace_back(ai, wi);
    }

    for (int i = 1; i <= n; i++) {
        dst[i] = INT_MAX;
    }
}

void solve() {
    priority_queue<pair<int, int>, vector<pair<int, int>>, greater<>> q;
    dst[1] = 0;
    q.push({0, 1});

    while (!q.empty()) {
        auto [distance, v] = q.top();
        q.pop();

        for (auto [u, weight]: adj[v]) {
            if (dst[v] + weight < dst[u]) {
                dst[u] = dst[v] + weight;
                q.push({dst[u], u});
                previous[u] = v;
            } else if (previous[u] > v) {
                previous[u] = v;
            }
        }
    }

    vector<int> odp;
    int x = n;
    while (x != 0) {
        odp.push_back(x);
        x = previous[x];
    }
    for (int i = odp.size() - 1; i >= 0; i--) {
        cout << odp[i] << ' ';
    }
}

int main() {
    read();
    solve();
    return 0;
}