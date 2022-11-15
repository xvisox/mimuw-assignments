#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define ull unsigned long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;

ll dp[100][100];
unordered_set<ll> paths;

void generate() {
    dp[0][0] = 1;
    int diff = 1;
    for (int i = 1; i <= 16; i++) {
        dp[0][i] = dp[0][i - 1] + diff;
        diff++;
    }
    for (int j = 1; j <= 16; j++) {
        dp[j][0] = dp[j - 1][1] + 1;
        diff = j + 1;
        for (int i = 1; i <= 16; i++) {
            dp[j][i] = dp[j][i - 1] + diff;
            diff++;
        }
    }
    int size = 5;
    for (int i = 0; i <= size; i++) {
        for (int j = 0; j <= size; j++) {
            cout << dp[i][j] << ' ';
        }
        cout << endl;
    }
    cout << endl;
}

void brute(int i, int j, int n, int m, ll sum) {
    if (i > n || j > m) return;
    if (i == n && j == m) {
        paths.insert(sum);
        return;
    }

    sum += dp[i][j];
    brute(i + 1, j, n, m, sum);
    brute(i, j + 1, n, m, sum);
}

int main() {
    FASTIO;
    generate();
    int size = 3;
    brute(0, 0, size, size, 0);
    cout << paths.size() << endl;
    return 0;
}