#include <bits/stdc++.h>

using namespace std;
constexpr int MAX_N = 1e5 + 1;
int t, n, k, z;
int dp[MAX_N];
int cost[MAX_N];

int main() {
    cin >> t;
    for (int i = 0; i < t; i++) {
        scanf("%d %d %d", &n, &k, &z);
        int sum = 0;
        scanf("%d", &cost[0]);
        sum += cost[0];
        for (int j = 1; j < n; j++) {
            scanf("%d", &cost[j]);
            if (j <= k) {
                sum += cost[j];
                dp[j] = max(cost[j] + cost[j - 1], dp[j - 1]);
            }
        }

        int maxSum = sum;
        int j = k;
        int ile = 0;
        // 1. symulacja, że ostatni ruch byl w lewo (j > 1 && z >= 1)
        // 2. zrobienie ruchu w miejscu (j > 2 && z >= 1)
        while (z > 0) {
            if (j > 1) {
                maxSum = max(maxSum, sum - cost[j] + cost[j - 2]);
            } else break;

            if (j > 2) {
                sum -= (cost[j] + cost[j - 1]);
                sum -= dp[j] * ile;
                ile++;
                sum += dp[j - 2] * ile;
                maxSum = max(maxSum, sum);
            }

            z--;
            j -= 2;
        }

        cout << maxSum << '\n';
    }

    return 0;
}