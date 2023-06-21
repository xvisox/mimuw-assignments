#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ull unsigned long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 1e5 + 1;
// ilosc 0/1/2 na prefiksie
ull tab[MAX_N], pref0[MAX_N], pref1[MAX_N], pref2[MAX_N];

int xd, m;

ull fast_binomial(ull n, ull k) {
    if (k > n) return 0;
    if (k == 0 || k == n) return 1;
    if (k == 1 || k == n - 1) return n;
    if (k > n / 2) k = n - k;
    ull res = 1;
    for (ull i = 1; i <= k; i++) {
        res *= n - k + i;
        res /= i;
    }
    return res;
}

int main() {
    FASTIO;
    cin >> xd >> m;
    for (int i = 1; i <= xd; i++) {
        cin >> tab[i];
    }

    ull sum = 0;
    for (int i = 1; i <= xd; i++) {
        sum += tab[i];
        sum %= 3;
        tab[i] = sum;
        pref0[i] = pref0[i - 1];
        pref1[i] = pref1[i - 1];
        pref2[i] = pref2[i - 1];
        if (sum == 0) pref0[i]++;
        else if (sum == 1) pref1[i]++;
        else pref2[i]++;
    }

    ull a, b, ones, twos, zeros;
    ull ans = 0;
    while (m--) {
        cin >> a >> b;
        zeros = pref0[b] - pref0[a - 1] + (tab[a - 1] == 0);
        ones = pref1[b] - pref1[a - 1] + (tab[a - 1] == 1);
        twos = pref2[b] - pref2[a - 1] + (tab[a - 1] == 2);
//        cout << zeros << " " << ones << " " << twos << endl;
        ans = fast_binomial(zeros, 2) + fast_binomial(ones, 2) + fast_binomial(twos, 2);
        cout << ans << endl;
    }

    return 0;
}