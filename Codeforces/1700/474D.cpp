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
constexpr int MOD = 1e9 + 7;
constexpr int MAX_N = 1e5 + 7;
int t, k;
int dp[MAX_N], odp[MAX_N];

void solve() {
    int ai, bi, temp;
    for (int i = 0; i < t; i++) {
        cin >> ai >> bi;
        temp = odp[bi] - odp[ai - 1];
        while (temp < 0) temp += MOD;
        cout << temp << endl;
    }
}

int main() {
    FASTIO;
    cin >> t >> k;
    fill_n(&dp[0], k, 1);
    dp[k] = 2;
    for (int i = k + 1; i < MAX_N; i++) {
        dp[i] = (dp[i - 1] + dp[i - k]) % MOD;
    }
    for (int i = 1; i < MAX_N; i++) {
        odp[i] = (odp[i - 1] + dp[i]) % MOD;
    }
    solve();


    return 0;
}

/* k = 4
 * 1
 * R
 * 2
 * RR
 * 3
 * RRR
 * 4
 * RRRR, WWWW
 * 5
 * RRRRR, RWWWW, WWWWR
 * 6
 * RRRRRR, RRWWWW, RWWWWR, WWWWRR
 * 7
 * RRRRRRR, RRRWWWW, RRWWWWR, RWWWWRR, WWWWRRR
 * 8
 * RRRRRRRR, RRRRWWWW, RRWWWWRR, RWWWWRRR, WWWWRRRR, RRRWWWWR, WWWWWWWW
 */
