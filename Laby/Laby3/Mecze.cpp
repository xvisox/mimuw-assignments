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
int n, m;
constexpr int MAX_N = 40'001;

string dp[MAX_N];

int main() {
    FASTIO;
    cin >> n >> m;
    char A = 'A';
    char B = 'B';

    int i, temp;
    while (m--) {
        i = 0;
        while (i < (n / 2)) {
            cin >> temp;
            dp[temp] += A;
            i++;
        }
        while (i < n) {
            cin >> temp;
            dp[temp] += B;
            i++;
        }
    }
    unordered_set<string> set;
    for (i = 1; i <= n; i++) {
        set.insert(dp[i]);
        if (set.size() != i) {
            cout << "NIE" << endl;
            return 0;
        }
    }

    cout << "TAK" << endl;
    return 0;
}