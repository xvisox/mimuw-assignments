#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
using namespace std;
unordered_map<int, int> mapka;

int main() {
    FASTIO;
    int t;
    cin >> t;
    int n, k, temp, sum;
    for (int i = 0; i < t; i++) {
        mapka.clear();
        cin >> n >> k;
        for (int j = 0; j < n; j++) {
            cin >> temp;
            mapka[temp]++;
        }
        sum = 0;
        for (auto el: mapka) {
            if (el.second > k) {
                sum += k;
            } else {
                sum += el.second;
            }
        }
        cout << sum << '\n';
    }

    return 0;
}