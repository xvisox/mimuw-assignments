#include <bits/stdc++.h>

#define ll long long

using namespace std;
constexpr int MAX_N = 1e5 + 1;
int dp[MAX_N];

ll ll_maks(ll a, ll b) {
    return a > b ? a : b;
}

int main() {
    int n;
    cin >> n;

    ll sum = 0, maks = 0;
    for (int i = 0; i < n; i++) {
        scanf("%d", &dp[i]);
        sum += dp[i];
        maks = ll_maks(maks, dp[i]);
    }
    if (sum % 2 == 1 || sum < 2 * maks) {
        cout << "NO\n";
        return 0;
    }
    cout << "YES\n";
    return 0;
}