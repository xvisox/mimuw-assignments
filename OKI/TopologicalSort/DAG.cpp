#include <bits/stdc++.h>

using namespace std;
constexpr int MAX_N = 1e6 + 1;
int n, m;
vector<int> adj[MAX_N];
vector<int> result;
bool visited[MAX_N];

void dfs(int s) {
    visited[s] = true;
    for (auto v: adj[s]) {
        if (!visited[v]) dfs(v);
    }
    result.push_back(s);
}

int main() {
    int v, u;
    scanf("%d %d", &n, &m);
    for (int i = 0; i < m; i++) {
        scanf("%d %d", &v, &u);
        adj[v].push_back(u);
    }
    for (int i = 1; i <= n; i++) {
        if (!visited[i]) dfs(i);
    }
    reverse(result.begin(), result.end());
    cout << result[0];
    for (int i = 1; i < n; i++) {
        cout << ' ' << result[i];
    }
    return 0;
}