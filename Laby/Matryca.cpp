#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define pll pair<ll, ll>
#define pii pair<int, int>
#define vi vector<int>
#define vii vector<pii>
#define vl vector<ll>
#define vll vector<pll>
#define endl '\n'
using namespace std;

int main() {
    FASTIO;
    string temp;
    cin >> temp;
    int n = temp.length();
    int i = 0, mini = INT_MAX, lastIdx = -1;
    char lastChar = '&';
    while (i < n) {
        if (temp[i] != '*') {
            if (lastChar == temp[i]) {
                lastIdx = i;
            } else {
                if (lastIdx != -1) mini = min(mini, i - lastIdx - 1);
                lastIdx = i;
                lastChar = temp[i];
            }
        }
        i++;
    }
    if (mini == INT_MAX) cout << 1 << endl;
    else cout << n - mini << endl;

    return 0;
}