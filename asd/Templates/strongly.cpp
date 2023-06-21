#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

int n, m;
constexpr int MAX_N = 1e5 + 7;
vector<int> adj[MAX_N], adj_rev[MAX_N];
vector<int> order, component;
bitset<MAX_N> vis;

void dfs1(int s) {
    vis[s] = true;
    for (auto u: adj[s]) {
        if (!vis[u]) dfs1(u);
    }
    order.push_back(s);
}

void dfs2(int s) {
    vis[s] = true;
    component.push_back(s);

    for (auto u: adj_rev[s]) {
        if (!vis[u]) dfs2(u);
    }
}

int main() {
    FASTIO;
    cin >> n;
    cin >> m;
    int ai, bi;
    while (m--) {
        cin >> ai >> bi;
        adj[ai].push_back(bi);
        adj_rev[bi].push_back(ai);
    }
    for (int i = 1; i <= n; i++) {
        if (!vis[i]) dfs1(i);
    }
    reverse(order.begin(), order.end());
    vis.reset();
    for (auto i: order) {
        if (!vis[i]) {
            dfs2(i);
            // process component
            component.clear();
        }
    }

    return 0;
}