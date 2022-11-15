#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define ull unsigned long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;

constexpr int MOD = 1e8;

int add(int a, int b) {
    a += b;
    if (a >= MOD)
        a -= MOD;
    return a;
}

int dp[201][201][2];

int main() {
    FASTIO;
    int n1, n2, k1, k2;
    cin >> n1 >> n2 >> k1 >> k2;

    dp[0][0][1] = 1;
    dp[0][0][0] = 1;

//    dp[1][0][0] = 1;
//    dp[0][1][1] = 1;

    int i = 1;
    while (i <= n1 + n2) {
        for (int j = i; j >= 0; j--) {
            // dodajemy n1
            for (int k = 1; k <= k1 && (j - k) >= 0; k++) {
                dp[j][i - j][0] = add(dp[j][i - j][0], dp[j - k][i - j][1]);
            }
            //dodajemy n2
            for (int k = 1; k <= k2 && (i - j - k) >= 0; k++) {
                dp[j][i - j][1] = add(dp[j][i - j][1], dp[j][i - j - k][0]);
            }
        }
        i++;
    }
//    cout << dp[0][2][1] << endl;
    cout << add(dp[n1][n2][1], dp[n1][n2][0]) << endl;
    return 0;
}