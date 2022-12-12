#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define ull unsigned long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;

constexpr int MAX_N = 1e5 + 1;
int n, m, k;
vector<int> cost;
vector<int> adj[MAX_N];
bitset<MAX_N> visited;
vector<int> ans;

void dfs(int v) {
    visited[v] = true;
    for (int u: adj[v]) {
        if (!visited[u])
            dfs(u);
    }
    ans.push_back(v);
}

void topological_sort() {
    for (int i = 1; i <= n; ++i) {
        if (!visited[i])
            dfs(i);
    }
    reverse(ans.begin(), ans.end());
}

int main() {
    FASTIO;
    cost.reserve(MAX_N);
    cin >> n >> m >> k;
    for (int i = 1; i <= n; i++) {
        cin >> cost[i];
    }
    int a, b;
    for (int i = 1; i <= m; i++) {
        cin >> a >> b;
        adj[b].push_back(a);
    }
    topological_sort();
    for (auto v: ans) {
        for (auto u: adj[v]) {
            cost[u] = max(cost[u], cost[v]);
        }
    }
    sort(cost.begin() + 1, cost.begin() + 1 + n);
    cout << cost[k] << endl;
    return 0;
}