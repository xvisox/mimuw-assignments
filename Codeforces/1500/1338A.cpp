#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
using namespace std;
constexpr int MAX_N = 1e5 + 1;
int tab[MAX_N];

void solve(int n) {
    int maks = tab[0], roznica = 0;
    for (int i = 1; i < n; i++) {
        if (maks < tab[i]) {
            maks = tab[i];
        } else {
            roznica = max(roznica, maks - tab[i]);
        }
    }
    if (roznica == 0) cout << 0 << '\n';
    else cout << floor(log2(roznica)) + 1 << '\n';
}

int main() {
    FASTIO;
    int t, n;
    cin >> t;
    for (int i = 0; i < t; i++) {
        cin >> n;
        for (int j = 0; j < n; j++) {
            cin >> tab[j];
        }
        solve(n);
    }


    return 0;
}