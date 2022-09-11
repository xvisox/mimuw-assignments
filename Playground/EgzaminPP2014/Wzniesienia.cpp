#include <bits/stdc++.h>

#define ll long long

constexpr int MAX_N = 500'001;
using namespace std;
vector<tuple<int, int, int>> edges; // {ai, bi, weight}
unordered_set<int> adj[MAX_N];
int n, m;
ll result;

void read() {
    cin >> n >> m;
    int ai, bi, wi;
    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &ai, &bi, &wi);
        edges.emplace_back(ai, bi, wi);
        adj[ai].insert(i);
        adj[bi].insert(i);
    }
}

int main() {
    read();
    int ai, bi, wi, weight;
    int i = 0;
    for (auto edge: edges) {
        tie(ai, bi, wi) = edge;
        for (auto idx: adj[ai]) {
            weight = get<2>(edges[idx]);
            if (weight != wi) result++;
        }
        adj[ai].erase(i);

        for (auto idx: adj[bi]) {
            weight = get<2>(edges[idx]);
            if (weight != wi) result++;
        }
        adj[bi].erase(i);
        i++;
    }
    cout << result << endl;
    return 0;
}