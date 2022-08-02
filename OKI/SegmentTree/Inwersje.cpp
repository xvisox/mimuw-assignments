#include <bits/stdc++.h>

using namespace std;

constexpr int base = 1 << 20;
int tree[base << 1];

void add(int v) {
    v = v + base;
    tree[v] = 1;
    v = v >> 1;
    while (v > 0) {
        tree[v] = tree[(v << 1)] + tree[(v << 1) + 1];
        v = v >> 1;
    }
}

int query(int a, int b) {
    int result = 0;
    a = a - 1 + base;
    b = b + 1 + base;
    while (a / 2 != b / 2) {
        if (a % 2 == 0) result += tree[a + 1];
        if (b % 2 == 1) result += tree[b - 1];
        a /= 2;
        b /= 2;
    }
    return result;
}

int main() {
    int n, tmp;
    cin >> n;
    vector<pair<int, int>> input;

    for (int i = 0; i < n; i++) {
        cin >> tmp;
        input.emplace_back(tmp, i);
    }
    sort(input.begin(), input.end());
    int compressed[n];
    tmp = 0;
    for (auto element: input) compressed[element.second] = tmp++;

    int result = 0;
    add(compressed[0]);
    for (tmp = 1; tmp < n; tmp++) {
        result += query(compressed[tmp] + 1, n);
        add(compressed[tmp]);
    }
    cout << result;
    return 0;
}
