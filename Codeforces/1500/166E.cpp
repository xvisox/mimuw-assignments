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
constexpr ll MOD = 1e9 + 7;

int main() {
    FASTIO;
    ll lastABC_1 = 1, lastD_1 = 0, lastABC_2, lastD_2;
    ll i = 1, n;
    cin >> n;
    while (i < n) {
        lastABC_2 = lastABC_1 * 2 + lastD_1;
        lastD_2 = 3 * lastABC_1;

        lastABC_1 = lastABC_2 % MOD;
        lastD_1 = lastD_2 % MOD;
        i++;
    }
    if (lastD_1 < 0) lastD_1 += MOD;
    cout << lastD_1 << endl;

    return 0;
}