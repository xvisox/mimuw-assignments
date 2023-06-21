#include <bits/stdc++.h>

using namespace std;

constexpr int MAX_N = 500001;
int n, m, k;
int deg[MAX_N]; // stopien v
vector<int> adj[MAX_N]; // to tylko do obliczenia
unordered_set<int> vertices[MAX_N]; // wierzcholki o stopniu i pod i-tym indeksem
unordered_set<int> removed; // usuniete wierzcholki

void compute() {
    for (int i = 1; i <= n; i++) {
        vertices[adj[i].size()].insert(i);
        deg[i] = adj[i].size();
    }
}

void read() {
    cin >> n >> m;
    int t1, t2;

    for (int i = 0; i < m; i++) {
        scanf("%d %d", &t1, &t2);
        adj[t1].push_back(t2);
        adj[t2].push_back(t1);
    }
}

int main() {
    read();
    compute();

    int v; // usuwany
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            if (!vertices[j].empty()) {
                v = *vertices[j].begin();
                vertices[j].erase(v);
                k = max(k, j);
                removed.insert(v);

                for (auto u: adj[v]) {
                    if (removed.find(u) != removed.end()) continue;
                    vertices[deg[u]].erase(u);
                    deg[u]--;
                    if (deg[u] >= 0) vertices[deg[u]].insert(u);
                }
                break;
            }
        }
    }

    cout << k << endl;
    return 0;
}