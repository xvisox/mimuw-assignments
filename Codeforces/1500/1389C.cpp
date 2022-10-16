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
int whosNext[10][10];
int dp[10][10];

void printarr() {
    for (auto &i: dp) {
        for (int j: i) {
            cout << j << ' ';
        }
        cout << endl;
    }
}

int main() {
    FASTIO;
    string temp;
    int t, conv, bigger, smaller;
    cin >> t;
    while (t--) {
        cin >> temp;
        fill_n(&whosNext[0][0], 100, -1);
        fill_n(&dp[0][0], 100, 0);
        for (char x: temp) {
            conv = x - '0';
            for (int i = 0; i < 10; i++) {
                if (conv == i) {
                    dp[i][i]++;
                    continue;
                }
                bigger = conv;
                smaller = i;
                if (bigger < smaller) swap(bigger, smaller);

                if (whosNext[smaller][bigger] == conv || whosNext[smaller][bigger] < 0) {
                    dp[smaller][bigger]++;
                    whosNext[smaller][bigger] = i;
                }
            }
        }

        // results
        int res1 = 0, res2 = 0;
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 10; j++) {
                if (i != j) {
                    res1 = max(res1, dp[i][j]);
                } else {
                    res2 = max(res2, dp[i][j]);
                }
            }
        }
        if (res1 % 2 == 1) res1--;
        cout << temp.length() - max(res1, res2) << endl;

        // debugging
//        printarr();
//        cout << endl;
    }

    return 0;
}

// 0135785152174082012097654604938957981703096740171424318330885652765893707675593434217828455171007143914259658511312169208710262035594955071894747649