#include <bits/stdc++.h>

using namespace std;

constexpr int MAX_N = 500001;
int n, m;
vector<pair<int, int>> adj[MAX_N];
int dst[MAX_N][2];
bool visited[MAX_N][2];

void read() {
    cin >> n >> m;

    int ai, bi, weight;
    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &ai, &bi, &weight);
        adj[ai].emplace_back(bi, weight);
        adj[bi].emplace_back(ai, weight);
    }
}

void bfs() {
    fill_n(&dst[0][0], MAX_N * 2, INT_MAX);
    queue<pair<int, int>> q;
    int v, lastWeight, u, weight;

    for (auto el: adj[1]) {
        u = el.first;
        weight = el.second;
        dst[u][weight] = 1;
        visited[u][weight] = true;
        q.push({u, weight});
    }

    while (!q.empty()) {
        v = q.front().first;
        lastWeight = q.front().second;
        q.pop();

        for (auto el: adj[v]) {
            u = el.first;
            weight = el.second;
            if (weight == lastWeight || visited[u][weight]) continue;

            dst[u][weight] = dst[v][lastWeight] + 1;
            visited[u][weight] = true;
            q.push({u, weight});
        }
    }
}

int main() {
    read();
    bfs();
    int tmp;
    for (int i = 2; i <= n; i++) {
        tmp = min(dst[i][0], dst[i][1]);
        if (tmp == INT_MAX) tmp = -1;
        cout << tmp << '\n';
    }

    return 0;
}