#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 500'001;
constexpr int LOG = 20;

int n;
vector<int> adj[MAX_N];
int up_V[MAX_N][LOG], up_U[MAX_N][LOG];
int depth_V[MAX_N], depth_U[MAX_N];
int input[MAX_N][2];

void read() {
    cin >> n;
    for (int i = 1; i <= n; i++) {
        cin >> input[i][0] >> input[i][1];
        if (input[i][0] > 0) {
            adj[input[i][0]].push_back(i);
            adj[i].push_back(input[i][0]);
        }
        if (input[i][1] > 0) {
            adj[input[i][1]].push_back(i);
            adj[i].push_back(input[i][1]);
        }
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

void get_diam(int s, int last, int lvl, int *diam, int *max_diam) {
    if (*max_diam < lvl) {
        *diam = s;
        *max_diam = lvl;
    }

    for (int v: adj[s]) {
        if (v == last) continue;
        get_diam(v, s, lvl + 1, diam, max_diam);
    }
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
    int diamV, diamU, max_diam = -1;
    get_diam(1, -1, 0, &diamV, &max_diam);
    max_diam = -1;
    get_diam(diamV, -1, 0, &diamU, &max_diam);

    // Obliczanie up
    dfs(diamU, -1, depth_U, up_U);
    dfs(diamV, -1, depth_V, up_V);

    solve();

    return 0;
}