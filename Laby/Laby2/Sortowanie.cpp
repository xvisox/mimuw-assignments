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
constexpr int MOD = 1e9;
constexpr int MAX_N = 1e3 + 1;
int tab[MAX_N];
// dp[dlugoscSlowa][ostatni/pierwszy indeks]
int dpLast[MAX_N][MAX_N], dpFirst[MAX_N][MAX_N];

int main() {
    FASTIO;
    int n, j;
    cin >> n;
    for (int i = 1; i <= n; i++) {
        cin >> tab[i - 1];
        dpLast[1][i - 1] = 1;
    }

    for (int i = 2; i <= n; i++) {
        j = 0;
        while (j + i <= n) {
            if (tab[j] < tab[j + 1]) {
                dpFirst[i][j] = dpFirst[i - 1][j + 1];
            }
            if (tab[j + i - 2] < tab[j + i - 1]) {
                dpLast[i][j + i - 1] = dpLast[i - 1][j + i - 2];
            }

            if (tab[j] < tab[j + i - 1]) {
                dpFirst[i][j] = (dpFirst[i][j] + dpLast[i - 1][j + i - 1]) % MOD;
                dpLast[i][j + i - 1] = (dpLast[i][j + i - 1] + dpFirst[i - 1][j]) % MOD;
            }
            j++;
        }
    }
    cout << (dpLast[n][n - 1] + dpFirst[n][0]) % MOD << endl;

    return 0;
}