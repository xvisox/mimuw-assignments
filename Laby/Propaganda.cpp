#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ul unsigned long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 1e5 + 2115;
constexpr int LOG = 18;
ul sparse[LOG + 1][MAX_N];
int lg[MAX_N];
int n, k;

bool check(int mid, ul q) {
    int l, r;
    ul res = 0;
    for (int i = 0; i < n; i++) {
        l = max(0, i - mid);
        r = min(i + mid, n - 1);
        int j = lg[r - l + 1];
        ul minimum = min(sparse[j][l], sparse[j][r - (1 << j) + 1]);
        res += minimum;
    }
    return res <= q;
}

ul query(ul q) {
    int l = 0, r = n - 1;
    while (l < r) {
        int mid = (l + r) / 2;
        if (check(mid, q)) {
            r = mid;
        } else {
            l = mid + 1;
        }
    }
    return l;
}

int main() {
    FASTIO;
    cin >> n >> k;
    for (int i = 0; i < n; i++) {
        cin >> sparse[0][i];
    }

    for (int i = 1; i <= LOG; i++)
        for (int j = 0; j + (1 << i) <= n; j++)
            sparse[i][j] = min(sparse[i - 1][j], sparse[i - 1][j + (1 << (i - 1))]);

    lg[1] = 0;
    for (int i = 2; i < MAX_N; i++)
        lg[i] = lg[i / 2] + 1;

    ul q;
    while (k--) {
        cin >> q;
        cout << query(q) << endl;
    }

    return 0;
}