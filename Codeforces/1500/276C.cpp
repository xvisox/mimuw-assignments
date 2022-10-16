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
constexpr int MAX_N = 2 * 1e5 + 1;
vector<ll> arr(MAX_N, 0);
vector<ll> dp(MAX_N, 0);

int main() {
    FASTIO;
    int n, q;
    cin >> n >> q;
    for (int i = 1; i <= n; i++) {
        cin >> arr[i];
    }
    sort(arr.begin(), arr.end(), greater<>());
    int ai, bi;
    for (int i = 0; i < q; i++) {
        cin >> ai >> bi;
        dp[ai - 1]++;
        dp[bi]--;
    }
    for (int i = 1; i <= n; i++) {
        dp[i] += dp[i - 1];
    }
    sort(dp.begin(), dp.end(), greater<>());
    ll res = 0;
    for (int i = 0; i < n; i++) {
        res += arr[i] * dp[i];
    }
    cout << res << endl;

    return 0;
}