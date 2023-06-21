#include <bits/stdc++.h>

#define MAX_N 500001

using namespace std;

int n, m, k;
int sajz[MAX_N], link[MAX_N];

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

int main() {
    scanf("%d %d %d", &n, &m, &k);
    for (int i = 1; i <= n; i++) {
        link[i] = i;
        sajz[i] = 1;
    }

    int cykle = 0;
    int ai, bi;
    for (int i = 0; i < m && cykle < 2; i++) {
        scanf("%d %d", &ai, &bi);
        if (!unite(ai, bi)) cykle++;
    }

    if (cykle == 2) {
        cout << -1 << endl;
        return 0;
    }

    int result = 0;
    for (int i = 0; i < k; i++) {
        scanf("%d %d", &ai, &bi);
        if (unite(ai, bi)) result++;
        else if (!cykle) {
            result++;
            cykle++;
        }
    }

    if (cykle)
        cout << result << endl;
    else
        cout << -1 << endl;
    return 0;
}