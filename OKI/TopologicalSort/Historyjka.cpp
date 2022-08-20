#include <bits/stdc++.h>

#define ll long long

using namespace std;

constexpr int MOD = 1e9 + 9;
constexpr int MAX_N = 1e6 + 1;
int n, m, src, dst;

vector<int> out[MAX_N];
vector<int> result;
ll dp[MAX_N];

void dfs(int s, bool visited[]) {
    visited[s] = true;
    for (auto v: out[s]) {
        if (!visited[v]) dfs(v, visited);
    }
    result.push_back(s);
}

void toposort() {
    bool visited[MAX_N];
    for (int i = 1; i <= n; i++) {
        if (!visited[i]) dfs(i, visited);
    }
    reverse(result.begin(), result.end());
}

int main() {
    int a, b;
    scanf("%d %d %d %d", &n, &m, &src, &dst);
    for (int i = 0; i < m; i++) {
        scanf("%d %d", &a, &b);
        out[a].push_back(b);
    }
    toposort();

    dp[dst] = 1;
    for (int i = n - 1; i >= 0; i--) {
        for (auto neigh: out[result[i]]) {
            dp[result[i]] = (dp[result[i]] + dp[neigh]) % MOD;
        }
        if (result[i] == src) break;
    }

    cout << dp[src] << endl;
    return 0;
}