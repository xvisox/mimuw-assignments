#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ul unsigned long long
#define endl '\n'
using namespace std;

int n;
constexpr int MAX_N = 2e5 + 1;
vector<pair<int, ul>> adj[MAX_N];
ul dst_v[MAX_N], dst_u[MAX_N];

void get_diam(int s, int last, ul dst, int *diam, ul *max_diam) {
    if (*max_diam <= dst) {
        *diam = s;
        *max_diam = dst;
    }

    for (auto &[u, w]: adj[s]) {
        if (u == last) continue;
        get_diam(u, s, dst + w, diam, max_diam);
    }
}

void read() {
    cin >> n;
    int u, v;
    ul w;
    for (int i = 1; i < n; i++) {
        cin >> u >> v >> w;
        adj[u].emplace_back(v, w);
        adj[v].emplace_back(u, w);
    }
}

void dfs(int s, int last, ul dst[]) {
    for (auto &[u, w]: adj[s]) {
        if (u == last) continue;
        dst[u] = dst[s] + w;
        dfs(u, s, dst);
    }
}

int main() {
    FASTIO;
    int diam_v, diam_u;
    ul max_diam = 0;
    read();
    get_diam(1, 0, 0, &diam_v, &max_diam);
    max_diam = 0;
    get_diam(diam_v, 0, 0, &diam_u, &max_diam);
    dfs(diam_v, 0, dst_v);
    dfs(diam_u, 0, dst_u);
    ul max_dst, res = ULONG_LONG_MAX;
    int res_v = 2115;
    for (int i = 1; i <= n; i++) {
        max_dst = max(dst_v[i], dst_u[i]);
        if (max_dst < res) {
            res_v = i;
            res = max_dst;
        }
    }
    cout << res_v << endl;

    return 0;
}