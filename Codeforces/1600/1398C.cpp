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
int n, t;
constexpr int MAX_N = 1e5 + 1;
ll tab[MAX_N]; // tab[i] -> {0, 1 ... 9}
unordered_map<ll, ll> cont;

int main() {
    FASTIO;
    cin >> t;
    string temp;
    while (t--) {
        cin >> n;
        cin >> temp;
        cont.clear();
        cont[1] = 1;
        ll sum = 0;
        for (int i = 0; i < n; i++) {
            tab[i] = temp[i] - '0';
            sum += tab[i];
            cont[sum - i]++;
        }
        ll res = 0;
        for (auto el: cont) {
            res += el.second * (el.second - 1) / 2;
        }
        cout << res << endl;
    };

    return 0;
}