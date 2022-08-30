#include <bits/stdc++.h>

#define MAX_L 200001
#define ll long long

using namespace std;

int n, l;
unordered_set<ll> col[MAX_L];
unordered_map<ll, int> res;

int main() {
    cin >> n >> l;
    ll temp;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < l; j++) {
            scanf("%lld", &temp);
            col[j].insert(temp);
        }
    }

    for (auto el: col[0]) {
        res[el] = 1;
    }
    int mx = 0;
    for (int i = 1; i < l; i++) {
        auto end = col[i - 1].end();
        for (auto el: col[i]) {
            if (col[i - 1].find(el) != end) {
                res[el]++;
            } else {
                mx = max(mx, res[el]);
                res[el] = 1;
            }
        }
    }

    for (auto el: res) {
        mx = max(mx, el.second);
    }
    cout << mx << endl;
    return 0;
}