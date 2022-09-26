#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
constexpr int MAX_N = 1e5 + 1;
using namespace std;
int T[MAX_N], X[MAX_N];

int main() {
    FASTIO;
    int t, n;
    cin >> t;
    int min1, max1;
    for (int i = 0; i < t; i++) {
        cin >> n;
        max1 = INT_MIN;
        min1 = INT_MAX;
        for (int j = 0; j < n; j++) cin >> X[j];
        for (int j = 0; j < n; j++) {
            cin >> T[j];
            min1 = min(min1, X[j] - T[j]);
            max1 = max(max1, X[j] + T[j]);
        }
        cout << fixed << ((long double) min1 + (long double) max1) / 2 << '\n';
    }

    return 0;
}