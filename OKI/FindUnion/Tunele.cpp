#include <bits/stdc++.h>

using namespace std;

constexpr int MAX_N = 1e5 + 1;
int sajz[MAX_N], link[MAX_N];
int n, m, k, components;

int find(int x) {
    int start = x;
    while (x != link[x]) x = link[x];
    return (link[start] = x);
}

bool unite(int a, int b) {
    a = find(a);
    b = find(b);
    if (a == b) return false;

    components--;
    if (sajz[a] > sajz[b]) {
        link[b] = a;
        sajz[a] += sajz[b];
    } else {
        link[a] = b;
        sajz[b] += sajz[a];
    }
    return true;
}

int main() {
    int x1, x2, i;
    scanf("%d %d %d", &n, &m, &k);
    for (i = 1; i <= n; i++) {
        sajz[i] = 1;
        link[i] = i;
    }

    int tab[m][2];
    for (i = 0; i < m; i++) {
        scanf("%d %d", &x1, &x2);
        tab[i][0] = x1;
        tab[i][1] = x2;
    }

    components = n;
    int result = -1;
    for (i = m - 1; i >= 0; i--) {
        unite(tab[i][0], tab[i][1]);
        if (components == k) {
            result = i + 1;
        } else if (components + 1 == k) {
            break;
        }
    }
    cout << result << endl;
    return 0;
}