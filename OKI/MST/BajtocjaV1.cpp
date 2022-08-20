#include <bits/stdc++.h>

// !!! TEN KOD Z JAKIEGOS WZGLEDU NIE DZIALA, IDK CO ZLE ZROBILEM !!!
#define LOG 19
#define MAX_N 7001
#define MAX_M 300001
#define TAK "TAK\n"
#define NIE "NIE\n"
#define PI pair<int, int>
#define TUP tuple<int, int, int>

using namespace std;

// MST
int n, m;
TUP edges[MAX_M];
PI sorted[MAX_M];
bitset<MAX_M> mst;
// LCA
int up[MAX_N][LOG], maks[MAX_N][LOG], depth[MAX_N];
unordered_map<size_t, int> waga;
vector<int> adj[MAX_N];

inline size_t key(int i, int j) { return (size_t) i << 32 | (unsigned int) j; }

int find(int x, int link[]) {
    int start = x;
    while (x != link[x]) x = link[x];
    return (link[start] = x);
}

bool unite(int a, int b, int link[], int sajz[]) {
    a = find(a, link);
    b = find(b, link);
    if (a == b) return false;

    if (sajz[a] < sajz[b]) swap(a, b);
    sajz[a] += sajz[b];
    link[b] = a;
    return true;
}

void getMST() {
    int link[MAX_N], sajz[MAX_N];
    for (int i = 1; i <= n; i++) {
        sajz[i] = 1;
        link[i] = i;
    }

    sort(sorted, sorted + m);
    int v, u, idx, weight;
    for (int i = 0; i < m; i++) {
        weight = sorted[i].first;
        idx = sorted[i].second;
        v = get<0>(edges[idx]);
        u = get<1>(edges[idx]);

        if (unite(v, u, link, sajz)) {
            mst[idx] = true;
            adj[v].push_back(u);
            adj[u].push_back(v);
            waga[key(v, u)] = weight;
            waga[key(u, v)] = weight;
        }
    }
}

int max_3(int a, int b, int c) {
    return max(max(a, b), c);
}

int getLCA(int a, int b) {
    int result = 0;
    if (depth[a] < depth[b]) {
        swap(a, b);
    }
    int k = depth[a] - depth[b];
    if (k > 0) {
        for (int j = LOG - 1; j >= 0; j--) {
            if (k & (1 << j)) {
                result = max(result, maks[a][j]);
                a = up[a][j];
            }
        }
    }
    if (a == b) return result;

    for (int j = LOG - 1; j >= 0; j--) {
        if (up[a][j] != up[b][j]) {
            result = max_3(result, maks[a][j], maks[b][j]);
            a = up[a][j];
            b = up[b][j];
        }
    }
    return max_3(maks[a][0], maks[b][0], result);
}

void dfs(int s, int last) {
    for (int v: adj[s]) {
        if (v == last) continue;

        depth[v] = depth[s] + 1;
        up[v][0] = s;
        maks[v][0] = waga[key(v, s)];
        for (int j = 1; j < LOG; j++) {
            up[v][j] = up[up[v][j - 1]][j - 1];
            maks[v][j] = max(maks[up[v][j - 1]][j - 1], maks[v][j - 1]);
        }
        dfs(v, s);
    }
}

void read() {
    scanf("%d %d", &n, &m);
    int v, u, w;
    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &v, &u, &w);
        edges[i] = {v, u, w}; // {edge between v <-> u}
        sorted[i] = {w, i}; // {weight, idx in edges array}
    }
}

int main() {
    read();
    getMST();

    int start = 1;
    for (int i = 1; i <= n; i++) {
        if (adj[i].size() == 1 || adj[i].size() == 2) {
            start = i;
            break;
        }
    }
    dfs(start, start);

    for (int i = 0; i < m; i++) {
        if (mst[i]) {
            cout << TAK;
        } else {
            auto [v, u, weight] = edges[i];

            cout << getLCA(v, u);
            if (getLCA(v, u) == weight) {
                cout << TAK;
            } else {
                cout << NIE;
            }
        }
    }
    return 0;
}
