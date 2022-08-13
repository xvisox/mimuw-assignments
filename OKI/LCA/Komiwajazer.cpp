#include <bits/stdc++.h>

#define LOG 16
#define MAX_N 30001
#define ENDL '\n'

using namespace std;

int n, m;
int up[MAX_N][LOG], depth[MAX_N];
vector<int> adj[MAX_N];

void dfs(int s, int last) {
    for (int v: adj[s]) {
        if (v == last) continue;

        depth[v] = depth[s] + 1;
        up[v][0] = s;
        for (int j = 1; j < LOG; j++) {
            up[v][j] = up[up[v][j - 1]][j - 1];
        }
        dfs(v, s);
    }
}

int get_lca(int a, int b) {
    if (depth[a] < depth[b]) {
        swap(a, b);
    }
    int k = depth[a] - depth[b];
    if (k > 0) {
        for (int j = LOG - 1; j >= 0; j--) {
            if (k & (1 << j)) {
                a = up[a][j];
            }
        }
    }
    if (a == b) return a;

    for (int j = LOG - 1; j >= 0; j--) {
        if (up[a][j] != up[b][j]) {
            a = up[a][j];
            b = up[b][j];
        }
    }
    return up[a][0];
}

void read() {
    cin >> n;
    int a, b;
    for (int i = 0; i < (n - 1); i++) {
        scanf("%d %d", &a, &b);
        adj[a].push_back(b);
        adj[b].push_back(a);
    }
}

int main() {
    read();
    dfs(1, 1);
    cin >> m;
    int t1, t2, temp, result = 0;
    scanf("%d", &t1);
    result += depth[t1];

    if (m == 1) {
        cout << result << ENDL;
        return 0;
    }
    for (int i = 0; i < m - 1; i++) {
        scanf("%d", &t2);
        temp = get_lca(t1, t2);
        result += (depth[t1] - depth[temp]);
        result += (depth[t2] - depth[temp]);
        t1 = t2;
    }
    cout << result << ENDL;
    return 0;
}
