#include <bits/stdc++.h>

#define S0 '\000'
#define S1 'K'
#define S2 'M'

#define MAX_N 300001

using namespace std;

bool res = true;
int n, m;
char state[MAX_N];
vector<int> adj[MAX_N];

void read() {
    cin >> n >> m;
    int ai, bi, ci;

    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &ai, &bi, &ci);
        while (bi <= ci) {
            adj[ai].push_back(bi);
            bi++;
        }
    }
}

void dfs(int s) {
    if (!res) return;
    state[s] = S1;

    for (auto v: adj[s]) {
        if (state[v] == S1) {
            res = false;
            return;
        } else if (state[v] == S0) {
            dfs(v);
        }
    }
    state[s] = S2;
    adj[s].clear();
}

// 58pkt, zapewne trzeba skorzystać z zapisu krawędzi w skondensowanej formie.
int main() {
    read();
    for (int v = 1; v <= n; v++) {
        if (state[v] == S0) {
            dfs(v);
        }
    }

    if (res) cout << "NIE" << endl;
    else cout << "TAK" << endl;
    return 0;
}
