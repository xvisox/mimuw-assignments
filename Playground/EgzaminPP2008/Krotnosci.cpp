#include <bits/stdc++.h>

#define POCZ 'a'
#define KON 'b'
#define ll long long
#define PI pair<char, ll>

using namespace std;

int n;
ll all;
set<int> indices;
unordered_map<ll, vector<PI>> mapka;
unordered_map<ll, ll> ile;

void read() {
    cin >> n;
    int ai, bi, ki;
    for (int i = 0; i < n; i++) {
        scanf("%d %d %d", &ai, &bi, &ki);
        indices.insert(ai);
        indices.insert(bi);
        mapka[ai].push_back({POCZ, ki});
        mapka[bi].push_back({KON, ki});
    }
}

void solve() {
    ll val = 0, lastIdx = 0;

    for (auto idx: indices) {
        if (lastIdx != 0) {
            ile[val] += (idx - lastIdx - 1);
            all += (idx - lastIdx - 1);
        }

        sort(mapka[idx].begin(), mapka[idx].end());
        auto it = mapka[idx].begin();
        auto end = mapka[idx].end();

        while (it->first == POCZ) {
            val += it->second;
            it++;
        }
        ile[val]++;
        all++;
        while (it != end) {
            val -= it->second;
            it++;
        }

        lastIdx = idx;
    }
}

int main() {
    read();
    solve();
    ll result = 0;
    ile.erase(0);
    for (auto el: ile) {
        result += (all - el.second) * el.second;
        all -= el.second;
    }
    cout << result << endl;
    return 0;
}