#include <bits/stdc++.h>

using namespace std;

#define MAX_N 7001
#define MAX_M 300001
#define TAK "TAK\n"
#define NIE "NIE\n"
#define PI pair<int, int>

int n, m;
int link[MAX_N], sajz[MAX_N];
PI sorted[MAX_M], edges[MAX_M];
bitset<MAX_M> mst;

int find(int x) {
    int start = x;
    while (x != link[x]) x = link[x];
    return (link[start] = x);
}

void unite(int a, int b) {
    a = find(a);
    b = find(b);
    if (a == b) return;

    if (sajz[a] < sajz[b]) swap(a, b);
    sajz[a] += sajz[b];
    link[b] = a;
}

void read() {
    scanf("%d %d", &n, &m);
    int v, u, w;
    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &v, &u, &w);
        edges[i] = {v, u}; // {edge between v <-> u}
        sorted[i] = {w, i}; // {weight, idx in edges array}
    }
}

bool same(int a, int b) {
    return find(a) == find(b);
}

void getMST() {
    for (int i = 1; i <= n; i++) {
        sajz[i] = 1;
        link[i] = i;
    }

    sort(sorted, sorted + m);
    int weight, lastWeight = sorted[0].first;
    int p = 0;
    vector<pair<int, int>> pointers;
    for (int i = 0; i < m; i++) {
        weight = sorted[i].first;
        if (weight != lastWeight) {
            pointers.emplace_back(p, i);
            p = i;
            lastWeight = weight;
        }
    }
    pointers.emplace_back(p, m);

    int v, u, idx;
    pair<int, int> e_prev, e_curr;
    for (int i = 1; i < pointers.size(); i++) {
        e_prev = pointers[i - 1];
        e_curr = pointers[i];

        for (int j = e_prev.first; j < e_prev.second; j++) {
            idx = sorted[j].second;
            v = edges[idx].first;
            u = edges[idx].second;
            unite(v, u);
        }

        for (int j = e_curr.first; j < e_curr.second; j++) {
            idx = sorted[j].second;
            v = edges[idx].first;
            u = edges[idx].second;
            if (same(v, u)) {
                mst[idx] = true;
            }
        }
    }
}

int main() {
    read();
    getMST();
    for (int i = 0; i < m; i++) {
        if (!mst[i]) cout << TAK;
        else cout << NIE;
    }
}