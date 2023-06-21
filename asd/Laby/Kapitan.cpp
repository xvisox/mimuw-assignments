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

constexpr int MAX_N = 200'001;
constexpr int INF = 1e9 + 7;
int n;
pair<int, int> x[MAX_N], y[MAX_N];
vector<pair<int, int>> adj[MAX_N];
int dist[MAX_N];
bitset<MAX_N> processed;

int get_weight(int i, pair<int, int> a[]) {
    return a[i].first - a[i - 1].first;
}

int main() {
    FASTIO;
    cin >> n;
    int temp;
    for (int i = 1; i <= n; i++) {
        cin >> temp;
        x[i] = {temp, i};
        cin >> temp;
        y[i] = {temp, i};
    }

    sort(x + 1, x + 1 + n);
    sort(y + 1, y + 1 + n);

    for (int i = 1; i <= n; i++) {
        if (i > 1) {
            adj[x[i].second].emplace_back(x[i - 1].second, get_weight(i, x));
            adj[y[i].second].emplace_back(y[i - 1].second, get_weight(i, y));
        }

        if (i < n) {
            adj[x[i].second].emplace_back(x[i + 1].second, get_weight(i + 1, x));
            adj[y[i].second].emplace_back(y[i + 1].second, get_weight(i + 1, y));
        }
    }

    for (int i = 0; i <= n; i++) {
        dist[i] = INF;
    }
    dist[1] = 0;

    priority_queue<pii, vector<pii >, greater<>> q;
    q.emplace(0, 1);
    while (!q.empty()) {
        auto [dst, v] = q.top();
        q.pop();
        if (processed[v]) continue;
        processed[v] = true;

        for (auto [u, weight]: adj[v]) {
            if (dist[v] + weight < dist[u]) {
                dist[u] = dist[v] + weight;
                q.emplace(dist[u], u);
            }
//            else if (dist[v] + weight == dist[u]) {
//                q.emplace(u, dist[u]);
//            }
        }
    }

    cout << dist[n] << endl;


    return 0;
}