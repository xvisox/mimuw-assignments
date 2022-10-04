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
#define BLUE 'B'
#define RED 'R'
using namespace std;
constexpr int MAX_N = 1001;
vector<int> adj[MAX_N];

int main() {
    FASTIO;
    int t;
    cin >> t;
    int n, x, ai, bi, dupa;
    while (t--) {
        cin >> n >> x;
        dupa = n;
        n--;
        while (n--) {
            cin >> ai >> bi;
            if (ai == x) {
                adj[x].push_back(bi);
            } else if (bi == x) {
                adj[x].push_back(ai);
            }
        }
        if (adj[x].size() <= 1) {
            cout << "Ayush\n";
        } else {
            if (dupa % 2 == 1) {
                cout << "Ashish\n";
            } else {
                cout << "Ayush\n";
            }
        }
        adj[x].clear();
    }

    return 0;
}