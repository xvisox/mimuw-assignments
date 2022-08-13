#include <bits/stdc++.h>

#define INF INT_MAX
#define PI pair<int, int>

using namespace std;
constexpr int MAX_N = 5001;
int n, m;
int koszt[MAX_N], dst[MAX_N], dst_rev[MAX_N];
bitset<MAX_N> processed;
vector<PI > normal[MAX_N];
vector<PI > reversed[MAX_N];

void dijkstra(int dstnce[], vector<PI > edges[]) {
    priority_queue<PI > q;
    dstnce[1] = 0;
    q.push({0, 1}); // {dst, vertex}

    int v, u, weight;
    while (!q.empty()) {
        v = q.top().second;
        q.pop();
        if (processed[v]) continue;
        processed[v] = true;

        for (auto element: edges[v]) {
            u = element.first;
            weight = element.second;

            if (dstnce[u] > dstnce[v] + weight) {
                dstnce[u] = dstnce[v] + weight;
                q.push({-dstnce[u], u});
            }
        }
    }
}

int main() {
    cin >> n;
    for (int i = 1; i <= n; i++) {
        scanf("%d", &koszt[i]);
        dst[i] = INF;
        dst_rev[i] = INF;
    }
    cin >> m;
    int v, u, weight;
    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &v, &u, &weight);
        normal[v].emplace_back(u, weight);
        reversed[u].emplace_back(v, weight);
    }

    dijkstra(dst, normal);
    processed.reset();
    dijkstra(dst_rev, reversed);

    long long minCost = INF, temp;
    for (int i = 1; i <= n; i++) {
        if (dst[i] == INF || dst_rev[i] == INF) continue;
        temp = (koszt[i] / 2) + dst[i] + dst_rev[i];
        minCost = min(minCost, temp);
    }
    cout << minCost << '\n';
    return 0;
}