#include <bits/stdc++.h>

using namespace std;
constexpr int MAX_N = 100'001;
constexpr int INF = 1e9;
int n, m;
int dir[MAX_N][3], dp[MAX_N];

int main() {
    cin >> n >> m;
    if (n % 2 == 1) {
        cout << -1 << endl;
        return 0;
    }

    int ai, bi, wi;
    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &ai, &bi, &wi);
        if (ai < bi) swap(ai, bi);
        dir[bi][ai - bi] = wi;
    }
    for (int i = 1; i <= n; i++) {
        dp[i] = INF;
    }

    for (int i = 1; i <= n; i += 2) {
        if (dir[i][1] > 0) {
            dp[i] = min(dp[i], dp[max(0, i - 2)] + dir[i][1]);
        }

        if (dir[i][2] > 0 && dir[i + 1][2] > 0) {
            dp[i + 2] = dp[max(0, i - 2)] + dir[i][2] + dir[i + 1][2];
        }
    }

    if (dp[n - 1] >= INF) cout << -1 << endl;
    else cout << dp[n - 1] << endl;
    return 0;
}