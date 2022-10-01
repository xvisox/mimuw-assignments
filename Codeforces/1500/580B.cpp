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
#define F first
#define S second
using namespace std;

ll ll_max(ll a, ll b) {
    return a > b ? a : b;
}

int main() {
    FASTIO;
    ll n, d;
    cin >> n >> d;
    ll mi, si;
    vll v;
    for (int i = 0; i < n; i++) {
        cin >> mi >> si;
        v.emplace_back(mi, si);
    }
    sort(v.begin(), v.end());
    ll sum = 0, maxSum = 0;
    ll l = 0, p = 0;
    while (p < v.size()) {
        if (v[p].F - v[l].F < d) {
            sum += v[p].S;
            p++;
        } else {
            sum -= v[l].S;
            l++;
        }
        maxSum = ll_max(sum, maxSum);
    }

    cout << maxSum << endl;
    return 0;
}