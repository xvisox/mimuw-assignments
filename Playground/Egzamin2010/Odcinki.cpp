#include <bits/stdc++.h>

#define START 's'
#define END 'e'
#define ll long long

using namespace std;

ll n;
unordered_map<ll, vector<pair<ll, char>>> mapka;
unordered_set<ll> indices;

void read() {
    cin >> n;
    ll x, y1, y2; // y1 < y2
    for (ll i = 0; i < n; i++) {
        scanf("%lld %lld %lld", &x, &y1, &y2);
        mapka[x].emplace_back(y1, START);
        mapka[x].emplace_back(y2, END);
        indices.insert(x);
    }
}

int main() {
    read();

    ll result = 0, inc;
    for (auto idx: indices) {
        inc = 0;
        sort(mapka[idx].begin(), mapka[idx].end());
        for (auto point: mapka[idx]) {
            if (point.second == START) {
                result += inc;
                inc++;
            } else {
                inc--;
            }
        }
    }
    cout << result << endl;
    return 0;
}