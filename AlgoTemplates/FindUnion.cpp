#include <bits/stdc++.h>

using namespace std;
constexpr int MAX_N = 1e9 + 7;

int n;
int link[MAX_N], sajz[MAX_N];

int find(int x) {
    int start = x;
    while (link[x] != x) x = link[x];
    return (link[start] = x);
}

void unite(int a, int b) {
    a = find(a);
    b = find(b);
    if (a == b) return;

    if (sajz[a] < sajz[b]) swap(a, b);
    link[b] = a;
    sajz[a] += sajz[b];
}

int main() {
    for (int i = 1; i <= n; i++) {
        sajz[i] = 1;
        link[i] = i;
    }

    return 0;
}