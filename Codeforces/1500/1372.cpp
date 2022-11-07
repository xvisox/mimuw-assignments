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

int n, t;
constexpr int MAX_N = 2 * 1e5 + 1;
int tab[MAX_N];

int main() {
    FASTIO;
    cin >> t;
    int i, licz;
    while (t--) {
        cin >> n;
        licz = 0;
        for (i = 1; i <= n; i++) {
            cin >> tab[i];
            if (tab[i] == i) licz++;
        }
        if (licz == n) {
            cout << 0 << endl;
            continue;
        }
        if (licz == 0) {
            cout << 1 << endl;
            continue;
        }

        int l = 1, r = n, ocz;
        while (tab[l] == l) l++;
        while (tab[r] == r) r--;
        ocz = r - l + 1;
        licz = 0;
        while (tab[l] != l && l <= r) {
            licz++;
            l++;
        }
        cout << (ocz == licz ? 1 : 2) << endl;
    }

    return 0;
}