#include <bits/stdc++.h>

#define MAX_N 200001

using namespace std;

int n, m;
int sajz[MAX_N], link[MAX_N];

int find(int x) {
    int start = x;
    while (link[x] != x) x = link[x];
    return (link[start] = x);
}

bool unite(int a, int b) {
    a = find(a);
    b = find(b);
    if (a == b) return false;

    if (sajz[a] < sajz[b]) {
        swap(a, b);
    }
    sajz[a] += sajz[b];
    link[b] = a;
    return true;
}

int main() {
    cin >> n >> m;
    int ai, bi;
    for (int i = 1; i <= n; i++) {
        link[i] = i;
        sajz[i] = 1;
    }

    for (int i = 0; i < m; i++) {
        scanf("%d %d", &ai, &bi);
        if (!unite(ai, bi)) {
            cout << "TAK" << endl;
            return 0;
        }
    }

    cout << "NIE" << endl;
    return 0;
}