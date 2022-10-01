#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
constexpr int MAX_N = 1e5 + 10;
using namespace std;
ll last[MAX_N];
vector<pair<ll, ll>> v;

int main() {
    FASTIO;
    ll n, xi, hi;
    cin >> n;
    last[0] = LLONG_MIN;
    v.emplace_back(0, 0);
    for (int i = 1; i <= n; i++) {
        cin >> xi >> hi;
        v.emplace_back(xi, hi);
    }
    v.emplace_back(LLONG_MAX, 0);

    ll result = 0;
    for (int i = 1; i <= n; i++) {
        tie(xi, hi) = v[i];
        if (last[i - 1] < xi - hi) {
            last[i] = xi;
            result++;
        } else {
            if (xi + hi < v[i + 1].first) {
                last[i] = xi + hi;
                result++;
            } else {
                last[i] = xi;
            }
        }
    }
    cout << result << endl;

    return 0;
}