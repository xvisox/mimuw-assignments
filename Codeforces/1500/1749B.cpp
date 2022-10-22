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
constexpr int MAX_N = 2 * 1e5 + 5;
ll tab[MAX_N];

int main() {
    FASTIO;
    // n-1 liczb b_i, i <- {1...n} musi być wziętych do sumy, więc najlepszym
    // przypadkiem będzie wzięcie każdej x1 (a nie x2 w przypadku brania ze środka)
    // i zostawienie ostatniej (największej) liczby
    int t;
    cin >> t;
    ll n, ans, temp;
    while (t--) {
        cin >> n;
        ans = 0;

        for (int i = 1; i <= n; i++) {
            cin >> temp;
            ans += temp;
        }
        for (int i = 1; i <= n; i++) {
            cin >> tab[i];
        }
        tab[n + 1] = 0;
        ll l = 1, p = n;
        while (l < p) {
            if (tab[l] < tab[p]) {
                ans += tab[l - 1];
                l++;
            } else {
                ans += tab[p + 1];
                p--;
            }
        }
        ans += tab[l - 1] + tab[p + 1];
        cout << ans << endl;
    }

    return 0;
}