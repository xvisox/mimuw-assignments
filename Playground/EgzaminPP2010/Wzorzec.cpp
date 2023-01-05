#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ull unsigned long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 101;
constexpr int MAX_LEN = 1e5 + 1;

int n, m;
string word;
vector<tuple<int, ull, int>> adj[MAX_N]; // {to, hash, len}
ull hash_pref[MAX_LEN], power_pref[MAX_LEN];
bool res[MAX_LEN][MAX_N]; // {i, j} - prefix do i (bez i-tego), ostatni wierzchołek j

// hash
constexpr int P = 31;
constexpr int MOD = 1e9 + 7;

ull get_hash(string &s) {
    ull hash = 0;
    for (char i: s) {
        hash = ((hash * P) % MOD + (i - 'a' + 1)) % MOD;
    }
    return hash;
}

void hash_word() {
    ull pow = 1;
    for (int i = 0; i < word.size(); ++i) {
        hash_pref[i] = ((hash_pref[i - 1] * P) % MOD + (word[i] - 'a' + 1)) % MOD;
        power_pref[i] = pow;
        pow = (pow * P) % MOD;
    }
}

ull interval(int l, int r) {
    if (l == 0) return hash_pref[r];
    return (hash_pref[r] - (hash_pref[l - 1] * power_pref[r - l + 1]) % MOD + MOD) % MOD;
}

int main() {
    FASTIO;
    cin >> n >> m;
    int ai, bi;
    string s;
    while (m--) {
        cin >> ai >> bi >> s;
        adj[ai].emplace_back(bi, get_hash(s), s.size());
    }

    cin >> word;
    hash_word();

    for (int j = 1; j <= n; j++) {
        res[0][j] = true;
    }

    auto word_len = word.size();
    for (int i = 0; i < word_len; ++i) {
        for (int j = 1; j <= n; ++j) {
            if (!res[i][j]) continue;

            for (auto &k: adj[j]) {
                int to, len;
                ull hash;
                tie(to, hash, len) = k;

                if (i + len <= word_len && hash == interval(i, i + len - 1)) {
                    res[i + len][to] = true;
                }
            }
        }
    }


    for (int i = 1; i <= n; ++i) {
        if (res[word_len][i]) {
            cout << "TAK\n";
            return 0;
        }
    }

    cout << "NIE\n";
    return 0;
}