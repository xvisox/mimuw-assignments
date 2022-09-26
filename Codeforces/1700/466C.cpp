#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
using namespace std;
constexpr int MAX_N = 5 * 1e5 + 1;
ll a[MAX_N], dp[MAX_N];

int main() {
    FASTIO;
    int n;
    cin >> n;
    for (int i = 1; i <= n; i++) {
        cin >> a[i];
        dp[i] = a[i] + dp[i - 1];
    }
    ll sum = dp[n];
    if (sum % 3 != 0) {
        cout << 0 << endl;
        return 0;
    }

    if (sum != 0) {
        ll first = (sum / 3), second = first * 2;
        ll firstCounter = 0, pairsCounter = 0, result = 0;
        for (int i = 1; i <= n; i++) {
            if (dp[i] == first) {
                firstCounter++;
            } else if (dp[i] == second) {
                pairsCounter += firstCounter;
            }
        }
        result += pairsCounter;
        cout << result << endl;
    } else {
        ll zeros = 0, zeroPairs = 0, zeroResult = 0;
        for (int i = 1; i < n; i++) {
            if (dp[i] == 0) {
                zeroPairs += zeros;
                zeros++;
            }
        }
        zeroResult += zeroPairs;
        cout << zeroResult << endl;
    }

    return 0;
}