#include <bits/stdc++.h>

#define MAX_N 500'001
#define ll long long

using namespace std;

vector<int> adj[MAX_N];
ll n, root = 1, temp;
ll sajz[MAX_N];
ll odp[MAX_N];
bitset<MAX_N> processed;

void read() {
    cin >> n;
    int ai, bi;
    for (int i = 1; i <= n - 1; i++) {
        scanf("%d %d", &ai, &bi);
        adj[ai].push_back(bi);
        adj[bi].push_back(ai);
        sajz[i] = 1;
    }
    sajz[n] = 1;
}

void dfs(int s, int last, int depth) {
    temp += depth;
    for (auto v: adj[s]) {
        if (last != v) dfs(v, s, depth + 1);
    }
    for (auto v: adj[s]) {
        if (last != v) sajz[s] += sajz[v];
    }
}

void solve() {
    queue<pair<int, ll>> q; // {v, pathsSum}
    processed[root] = true;
    for (auto u: adj[root]) {
        q.push({u, temp});
    }
    odp[root] = temp;

    ll currPathsSum;
    while (!q.empty()) {
        auto [v, pathsSum] = q.front();
        processed[v] = true;
        q.pop();

        currPathsSum = (ll) (pathsSum + n - (2 * sajz[v]));
        odp[v] = currPathsSum;
        for (auto u: adj[v]) {
            if (!processed[u]) {
                q.push({u, currPathsSum});
            }
        }
    }
}

int main() {
    read();
    dfs(root, 0, 0);
    solve();
    for (int i = 1; i <= n; i++) {
        cout << odp[i] << '\n';
    }
    return 0;
}