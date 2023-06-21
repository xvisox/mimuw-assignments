#include <bits/stdc++.h>

#define MAX_N 100001
#define PI pair<int, int>

using namespace std;

int n, m, a, b, d;
vector<tuple<int, int, int>> adj[MAX_N];
bitset<MAX_N> processed;
int dst[MAX_N];
int res1, res2;

void read() {
    scanf("%d %d %d %d %d", &n, &m, &a, &b, &d);
    int n1, n2, c1, c2, p1, p2;
    for (int i = 0; i < m; i++) {
        scanf("%d %d %d %d  %d %d", &n1, &n2, &c1, &p1, &c2, &p2);
        adj[n1].emplace_back(n2, c1, p1);
        adj[n2].emplace_back(n1, c2, p2);
    }
}

void dijkstra(int s, int k) {
    for (int i = 1; i <= n; i++) dst[i] = INT_MAX;
    processed.reset();
    priority_queue<PI, vector<PI >, greater<>> q;
    q.push({0, s});
    dst[s] = 0;

    int v;
    while (!q.empty()) {
        v = q.top().second;
        q.pop();
        if (processed[v]) continue;
        processed[v] = true;

        for (auto el: adj[v]) {
            auto [u, weight, inc] = el;
            if (dst[v] + weight < dst[u]) {
                dst[u] = dst[v] + weight;
                q.push({dst[u], u});
            }
        }
        if (v == k) return;
    }
}

void update() {
    for (int i = 1; i <= n; i++) {
        for (int j = 0; j < adj[i].size(); j++) {
            auto [u, weight, inc] = adj[i][0];
            adj[i].emplace_back(u, weight + (inc * (d - 1)), 0);
            adj[i].erase(adj[i].begin());
        }
    }
}

int solve() {
    int ab, ba;
    dijkstra(a, b);
    ab = dst[b];
//    cout << ab << endl;
    dijkstra(b, a);
    ba = dst[a];
//    cout << ba << endl;
    update();
    return ab + ba;
}

int main() {
    read();
    res1 = solve();
    update();
    res2 = solve();
    cout << min(res1, res2) << endl;
    return 0;
}