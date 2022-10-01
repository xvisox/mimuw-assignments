#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
constexpr int MAX_N = 1e5 + 10;
using namespace std;
ll tab[MAX_N], ile[MAX_N];
ll maks;

int main() {
    FASTIO;
    int n;
    cin >> n;
    for (int i = 0; i < n; i++) {
        cin >> tab[i];
        ile[tab[i]]++;
        maks = max(maks, tab[i]);
    }
    tab[0] = 0;
    tab[1] = ile[1];
    for (int i = 2; i <= maks; i++) {
        tab[i] = max(tab[i - 1], tab[i - 2] + ile[i] * i);
    }
    cout << tab[maks] << endl;
    return 0;
}