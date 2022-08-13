#include <bits/stdc++.h>

using namespace std;

int n, q, v, u, t;

int find(int x, int link[]) {
    int start = x;
    while (link[x] != x) x = link[x];
    return (link[start] = x);
}

void unite(int a, int b, int link[], int sajz[]) {
    a = find(a, link);
    b = find(b, link);

    if (a == b) return;
    if (sajz[a] > sajz[b]) {
        sajz[a] += sajz[b];
        link[b] = a;
    } else {
        sajz[b] += sajz[a];
        link[a] = b;
    }
}

bool same(int a, int b, int link[]) {
    return find(a, link) == find(b, link);
}

int main() {
    cin >> n >> q;
    int link[n + 1], sajz[n + 1];
    for (int i = 1; i <= n; i++) {
        link[i] = i;
        sajz[i] = 1;
    }
    for (int i = 0; i < q; i++) {
        scanf("%d %d %d", &t, &v, &u);
        if (t == 1) {
            unite(v, u, link, sajz);
        } else {
            if (same(v, u, link)) {
                cout << "TAK\n";
            } else {
                cout << "NIE\n";
            }
        }
    }
    return 0;
}