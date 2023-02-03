#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 3e5 + 2115;
int n, k;
string s;
size_t sajz;
int tab[MAX_N], pref[MAX_N];
unordered_map<int, pair<int, int>> range;
char result[MAX_N];

int main() {
    FASTIO;
    cin >> n >> k;
    cin >> s;
    int ai, bi, mid;
    while (k--) {
        cin >> ai >> bi;
        ai--;
        bi--;

        tab[ai]++;
        tab[bi + 1]--;
        mid = (ai + bi) / 2;
        if (range.find(mid) == range.end()) {
            range[mid] = {ai, bi};
        } else {
            range[mid].first = min(range[mid].first, ai);
            range[mid].second = max(range[mid].second, bi);
        }
    }

    sajz = s.size();
    for (int i = 0; i < sajz; i++) {
        pref[i] = pref[max(0, i - 1)] + tab[i];
    }
    fill_n(&result[0], sajz, 'X');

    for (auto element: range) {
        int l = element.second.first;
        int r = element.second.second;
        for (int i = l; i <= r; i++) {
            if (pref[i] % 2 == 0) {
                result[i] = s[i];
            } else {
                result[i] = s[r - i + l];
            }
        }
    }

    for (int i = 0; i < sajz; i++) {
        if (result[i] == 'X') {
            result[i] = s[i];
        }
    }

    cout << result << endl;


    return 0;
}