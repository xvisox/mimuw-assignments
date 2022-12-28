#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define MAX_N 100001

using namespace std;

int n, m;
vector<pair<int, int>> adj[MAX_N];
int dst[MAX_N];
vector<int> previous[MAX_N];
bool processed[MAX_N];

void read() {
    FASTIO;
    cin >> n >> m;
    int ai, bi, wi;
    for (int i = 0; i < m; i++) {
        cin >> ai >> bi >> wi;
        adj[ai].emplace_back(bi, wi);
        adj[bi].emplace_back(ai, wi);
    }

    for (int i = 1; i <= n; i++) {
        dst[i] = INT_MAX;
    }
}

void solve() {
    priority_queue<pair<int, int>, vector<pair<int, int>>, greater<>> q;
    dst[n] = 0;
    previous[n].push_back(-1);
    q.emplace(0, n);

    while (!q.empty()) {
        auto [distance, v] = q.top();
        q.pop();
        if (processed[v]) continue;
        processed[v] = true;

        for (auto [u, weight]: adj[v]) {
            if (dst[v] + weight < dst[u]) {
                dst[u] = dst[v] + weight;
                q.emplace(dst[u], u);
                previous[u].clear();
                previous[u].push_back(v);
            } else if (dst[v] + weight == dst[u]) {
                previous[u].push_back(v);
            }
        }
    }
}

int get_min(vector<int> &v) {
    int min = INT_MAX;
    for (auto &i: v) {
        if (i < min) {
            min = i;
        }
    }
    return min;
}

void print() {
    int x = 1;
    while (x != -1) {
        cout << x << " ";
        x = get_min(previous[x]);
    }
}

int main() {
    read();
    solve();
    print();
    return 0;
}