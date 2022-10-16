#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;
int n, k, d;
constexpr int MAX_N = 101;
constexpr int MOD = 1e9 + 7;
int dp[MAX_N][2];

int main() {
    FASTIO;
    cin >> n >> k >> d;
    int i = 1, m;
    while (i <= k) {
        dp[i][i >= d] = 1;
        i++;
    }
    i = 2;
    int diff;
    while (i <= n) {
        m = i - 1;
        while (m >= 1 && (i - m <= k)) {
            diff = i - m;
            dp[i][1] = (dp[i][1] + dp[m][1]) % MOD;
            dp[i][diff >= d] = (dp[i][diff >= d] + dp[m][0]) % MOD;
            m--;
        }
        i++;
    }
    cout << dp[n][1] << endl;


    return 0;
}