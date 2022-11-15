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

constexpr int MAX_N = 500'001;
constexpr int LOG = 20;

int n;
vector<int> adj[MAX_N];
int level[MAX_N], node[MAX_N];
int up_V[MAX_N][LOG], up_U[MAX_N][LOG];
int depth_V[MAX_N], depth_U[MAX_N];
int input[MAX_N][2];

void read() {
    cin >> n;
    for (int i = 1; i <= n; i++) {
        cin >> input[i][0] >> input[i][1];
        if (input[i][0] > 0) adj[i].push_back(input[i][0]);
        if (input[i][1] > 0) adj[i].push_back(input[i][1]);
    }
}

void dfs(int s, int last, int depth[], int up[][LOG]) {
    for (int v: adj[s]) {
        if (v == last) continue;
        depth[v] = depth[s] + 1;
        up[v][0] = s;
        for (int j = 1; j < LOG; j++) {
            up[v][j] = up[up[v][j - 1]][j - 1];
        }
        dfs(v, s, depth, up);
    }
}

void diam(int s) {
    if (adj[s].empty()) {
        level[s] = 1;
        node[s] = s;
        return;
    }

    for (int v: adj[s]) {
        diam(v);
        if (level[s] < level[v]) {
            level[s] = level[v];
            node[s] = node[v];
        }
    }
    level[s]++;
}

int lift(int v, int d, int up[][LOG]) {
    for (int j = LOG - 1; j >= 0; j--) {
        if (d & (1 << j)) {
            v = up[v][j];
        }
    }
    return v;
}

void solve() {
    int m;
    cin >> m;
    int v, d;
    while (m--) {
        cin >> v >> d;
        if (depth_U[v] >= d) {
            cout << lift(v, d, up_U);
        } else if (depth_V[v] >= d) {
            cout << lift(v, d, up_V);
        } else {
            cout << -1;
        }
        cout << endl;
    }
}

int main() {
    FASTIO;
    read();
    // Obliczanie srednicy
    int diamV, diamU;
    diam(adj[1][0]);
    if (adj[1].size() == 1) {
        diamU = 1;
    } else {
        diam(adj[1][1]);
        diamU = node[adj[1][1]];
    }
    diamV = node[adj[1][0]];
    // cout << diamV << ' ' << diamU << endl;
    for (int i = 1; i <= n; i++) {
        if (input[i][0] > 0) {
            adj[input[i][0]].push_back(i);
        }
        if (input[i][1] > 0) {
            adj[input[i][1]].push_back(i);
        }
    }
    // Obliczanie up
    dfs(diamU, -1, depth_U, up_U);
    dfs(diamV, -1, depth_V, up_V);

    solve();

    return 0;
}