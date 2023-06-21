#include <bits/stdc++.h>

using namespace std;
constexpr int MAX_N = 1e9 + 7;

int n;
int parent[MAX_N], sajz[MAX_N];

int find(int x) {
    if (x == parent[x])
        return x;
    return parent[x] = find(parent[x]);
}

void unite(int a, int b) {
    a = find(a);
    b = find(b);
    if (a == b) return;

    if (sajz[a] < sajz[b]) swap(a, b);
    parent[b] = a;
    sajz[a] += sajz[b];
}

int main() {
    for (int i = 1; i <= n; i++) {
        sajz[i] = 1;
        parent[i] = i;
    }

    return 0;
}