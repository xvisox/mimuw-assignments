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
ll ile[4], koszt[4], przepis[4]; // B -> 1, S -> 2, C -> 3
ll budzet;

ll ll_max(ll a, ll b) {
    return a > b ? a : b;
}

bool check(ll mid) {
    int i = 1;
    ll nowe[4];
    ll sum = 0;
    while (i <= 3) {
        nowe[i] = ll_max(0, przepis[i] * mid - ile[i]) * koszt[i];
        sum += nowe[i];
        i++;
    }
    return sum <= budzet;
}

int main() {
    FASTIO;
    string temp;
    cin >> temp;
    for (auto i: temp) {
        if (i == 'B') {
            przepis[1]++;
        } else if (i == 'S') {
            przepis[2]++;
        } else {
            przepis[3]++;
        }
    }

    int i = 1;
    while (i <= 3) {
        cin >> ile[i];
        i++;
    }
    i = 1;
    while (i <= 3) {
        cin >> koszt[i];
        i++;
    }
    cin >> budzet;
    ll l = 0, p = 100000000000000, mid;
    while (l < p) {
        mid = (l + p) / 2;
        if (check(mid)) {
            l = mid + 1;
        } else {
            p = mid;
        }
    }
    cout << l - 1 << endl;
    return 0;
}