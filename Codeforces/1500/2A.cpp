#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
using namespace std;
unordered_map<string, int> mapka, m1;
vector<pair<string, int>> v;

int main() {
    FASTIO;
    int n;
    cin >> n;
    string name;
    int score, maxScore = INT_MIN;
    for (int i = 0; i < n; i++) {
        cin >> name;
        cin >> score;
        mapka[name] += score;
        v.emplace_back(name, score);
    }
    for (const auto &el: mapka) maxScore = max(maxScore, el.second);
    for (auto [nm, sc]: v) {
        m1[nm] += sc;
        if (m1[nm] >= maxScore && mapka[nm] == maxScore) {
            cout << nm << endl;
            return 0;
        }
    }

    return 0;
}