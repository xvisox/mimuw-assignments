#include <bits/stdc++.h>

#define MAX_N 300001

using namespace std;
int n, m;
unordered_map<int, vector<int>> adj;
int in[MAX_N];

void read() {
    cin >> n >> m;
    int ai, bi, ci;

    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &ai, &bi, &ci);
        while (bi <= ci) {
            adj[ai].push_back(bi);
            in[bi]++;
            bi++;
        }
    }
}

int main() {
    read();

    unordered_set<int> nodes;
    for (int i = 1; i <= n; i++) {
        if (in[i] == 0) {
            nodes.insert(i);
        }
    }

    int v;
    while (!nodes.empty()) {
        v = *nodes.begin();
        nodes.erase(nodes.begin());
        for (auto u: adj[v]) {
            in[u]--;
            if (in[u] == 0) {
                nodes.insert(u);
            }
        }
        adj[v].clear();
    }

    for (int i = 1; i <= n; i++) {
        if (in[i] > 0) {
            cout << "TAK" << endl;
            return 0;
        }
    }

    cout << "NIE" << endl;
    return 0;
}