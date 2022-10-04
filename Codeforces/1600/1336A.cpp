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
int n, k;
constexpr int MAX_N = 2 * 1e5 + 1;
vector<int> adj[MAX_N];
ll ile[MAX_N];
priority_queue<ll> paths;

void dfs(int s, int last, int len) {
    ile[s]++;
    for (auto v: adj[s]) {
        if (last != v) {
            dfs(v, s, len + 1);
            ile[s] += ile[v];
        }
    }
    paths.push(ile[s] - 1 - len);
}

int main() {
    FASTIO;
    int ai, bi;
    cin >> n >> k;
    for (int i = 1; i < n; i++) {
        cin >> ai >> bi;
        adj[ai].push_back(bi);
        adj[bi].push_back(ai);
    }
    dfs(1, 0, 0);
    ll i = n - k, sum = 0;
    while (i > 0) {
        sum += paths.top();
        paths.pop();
        i--;
    }
    cout << sum << endl;
    return 0;
}