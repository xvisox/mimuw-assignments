#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)

using namespace std;
constexpr int MAX_BASE = 1 << 17;
int tree[MAX_BASE << 1];
int n, m, base;

void add(int v, int x) {
    v += base;
    tree[v] = x;
    v /= 2;
    int i = 1;
    while (v > 0) {
        if (i % 2 == 1) {
            tree[v] = tree[2 * v] | tree[2 * v + 1];
        } else {
            tree[v] = tree[2 * v] ^ tree[2 * v + 1];
        }
        i++;
        v /= 2;
    }
}

int main() {
    FASTIO;
    cin >> n >> m;
    base = 1 << n;
    int temp;
    for (int i = 0; i < base; i++) {
        cin >> temp;
        add(i, temp);
    }
    int pi, bi;
    for (int i = 0; i < m; i++) {
        cin >> pi >> bi;
        add(pi - 1, bi);
        cout << tree[1] << '\n';
    }

    return 0;
}