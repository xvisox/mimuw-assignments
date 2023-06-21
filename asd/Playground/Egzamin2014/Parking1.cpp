#include <bits/stdc++.h>

#define MAX_N 500001

using namespace std;

int n, m;
bool input[MAX_N], visited[MAX_N];
vector<int> adj[MAX_N];

void dfs(int s) {
    visited[s] = true;
    if (input[s]) return;

    for (auto u: adj[s]) {
        if (!visited[u]) {
            dfs(u);
        }
    }
}

int main() {
    cin >> n >> m;
    for (int i = 1; i <= n; i++) {
        scanf("%d", &input[i]);
    }
    int ai, bi;
    for (int i = 0; i < m; i++) {
        scanf("%d %d", &ai, &bi);
        adj[ai].push_back(bi);
        adj[bi].push_back(ai);
    }
    dfs(1);
    for (int i = 1; i <= n; i++) {
        if (visited[i] && input[i]) {
            cout << i << '\n';
        }
    }

    return 0;
}