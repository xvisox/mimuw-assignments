#include <bits/stdc++.h>

#define MAX_N 100001
#define MAX_M 300001
#define PI pair<int, int>

using namespace std;

int n, m, counter;
int link[MAX_N], sajz[MAX_N], mst[MAX_M];
PI edges[MAX_M], sorted[MAX_M];

int find(int x) {
    int start = x;
    while (x != link[x]) x = link[x];
    return (link[start] = x);
}

bool unite(int a, int b) {
    a = find(a);
    b = find(b);
    if (a == b) return false;

    if (sajz[a] < sajz[b]) swap(a, b);
    sajz[a] += sajz[b];
    link[b] = a;
    return true;
}

void getMST() {
    int v, u, idx, weight;
    for (int i = m - 1; i >= 0; i--) {
        idx = sorted[i].second;
        weight = sorted[i].first;
        v = edges[idx].first;
        u = edges[idx].second;
        if (unite(v, u)) {
            mst[idx] = weight;
            counter++;
        }
    }
}

int main() {
    scanf("%d %d", &n, &m);
    for (int i = 1; i <= n; i++) {
        link[i] = i;
        sajz[i] = 1;
    }

    int v, u, weight;
    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &v, &u, &weight);
        edges[i] = {v, u};
        sorted[i] = {weight, i};
    }
    sort(sorted, sorted + m);

    getMST();
    cout << n - counter << endl;
    for (int i = 0; i < m && counter; i++) {
        if (mst[i] == 0) {
            if (counter == 1) {
                cout << i + 1;
            } else {
                cout << i + 1 << ' ';
            }
            counter--;
        }
    }
    return 0;
}