#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 200'001;
vector<int> adj[MAX_N];
int f[MAX_N];
bitset<MAX_N> visited;
int start[11];
int curr_max[11], end_max[11];
int n;

void read() {
    cin >> n;
    for (int i = 1; i <= n; ++i) {
        cin >> f[i];
    }
    int a, b;
    for (int i = 0; i < n - 1; ++i) {
        cin >> a >> b;
        adj[a].push_back(b);
        adj[b].push_back(a);
    }
}

void dfs(int s, int depth) {
    visited[s] = true;
    if (curr_max[f[s]] < depth) {
        curr_max[f[s]] = depth;
        start[f[s]] = s;
    }
    for (auto u: adj[s]) {
        if (!visited[u]) {
            dfs(u, depth + 1);
        }
    }
}

void dfs_2(int s, int depth, int fabryka) {
    visited[s] = true;
    if (f[s] == fabryka && end_max[fabryka] < depth) {
        end_max[fabryka] = depth;
    }
    for (auto u: adj[s]) {
        if (!visited[u]) {
            dfs_2(u, depth + 1, fabryka);
        }
    }
}

int main() {
    FASTIO;
    read();
    for (int i = 1; i <= 10; i++) {
        start[i] = -1;
        curr_max[i] = -1;
        end_max[i] = -1;
    }
    for (int i = 1; i <= n; ++i) {
        if (!visited[i]) {
            dfs(i, 0);
        }
    }
    int res = -1;
    for (int i = 1; i <= 10; i++) {
        if (start[i] != -1) {
            visited.reset();
            dfs_2(start[i], 0, i);
            res = max(res, end_max[i]);
        }
    }
    cout << res << endl;

    return 0;
}