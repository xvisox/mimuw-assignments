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

int main() {
    FASTIO;
    int t, n, last;
    cin >> t;
    string tmp;
    vector<int> odp;
    while (t--) {
        last = 0;
        stack<int> s0, s1; // konczace sie na 0 i 1
        odp.clear();
        cin >> n;
        cin >> tmp;
        for (char x: tmp) {
            if (x == '1') {
                if (s0.empty()) {
                    odp.push_back(++last);
                    s1.push(last);
                } else {
                    odp.push_back(s0.top());
                    s1.push(s0.top());
                    s0.pop();
                }
            } else {
                if (s1.empty()) {
                    odp.push_back(++last);
                    s0.push(last);
                } else {
                    odp.push_back(s1.top());
                    s0.push(s1.top());
                    s1.pop();
                }
            }
        }
        cout << last << endl;
        for (int el: odp) {
            cout << el << ' ';
        }
        cout << endl;
    }


    return 0;
}