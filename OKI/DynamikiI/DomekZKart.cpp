#include <bits/stdc++.h>

using namespace std;

constexpr int MAX = 1 << 17;

int n;
int input[MAX];
int dp[MAX][21];

void traverse(int v, int k, int lvl) {
    if (k == 0) return;

    dp[v][1] = input[v];
    if (lvl == n) return;

    traverse(2 * v, k - 1, lvl + 1);
    traverse(2 * v + 1, k - 1, lvl + 1);

    for (int i = 2; i <= k; i++) {
        for (int j = 0; j < i; j++) {
            dp[v][i] = max(dp[v][i], input[v] + dp[2 * v][j] + dp[2 * v + 1][i - j - 1]);
        }
    }
}

int main() {
    int k, base, temp;
    cin >> n >> k;
    base = 1 << n;
    for (int i = 1; i < base; i++) {
        cin >> input[i] >> temp;
        input[i] += temp;
    }
    k /= 2;
    traverse(1, k, 1);
    cout << dp[1][k] << endl;
    return 0;
}
