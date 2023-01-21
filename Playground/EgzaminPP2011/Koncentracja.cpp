#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define pll pair<ll, ll>
#define ll long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 2e3 + 1;
vector<ll> adj[MAX_N];
vector<pll > points;
ll n, d;
ll col[MAX_N];
ll dst[MAX_N][MAX_N];

void dfs(ll s, ll last, bool *ok) {
    if (!(*ok)) return;

    ll curr = 1 - last;
    col[s] = curr;

    for (auto u: adj[s]) {
        if (col[u] != -1 && col[u] == curr) {
            *ok = false;
            return;
        } else if (col[u] == -1) {
            dfs(u, curr, ok);
        }
    }
}

bool is_bipartite() {
    bool ok = true;
    for (int i = 0; i < n && ok; i++) {
        if (col[i] == -1) {
            ll color = 0;
            for (int j = 0; j < n; j++) {
                if (col[j] != -1) {
                    color = dst[i][j] <= d ? col[j] : 1 - col[j];
                    break;
                }
            }
            dfs(i, color, &ok);
        }
    }
    return ok;
}

int main() {
    FASTIO;
    cin >> n >> d;
    ll ai, bi;
    fill_n(&col[0], MAX_N, -1);
    for (int i = 0; i < n; i++) {
        cin >> ai >> bi;
        points.emplace_back(ai, bi);
    }

    for (int i = 0; i < n; i++) {
        for (int j = i; j < n; j++) {
            ll distance = (points[i].first - points[j].first) * (points[i].first - points[j].first) +
                          (points[i].second - points[j].second) * (points[i].second - points[j].second);
            dst[i][j] = dst[j][i] = distance;
            if (distance > d * d) {
                adj[i].push_back(j);
                adj[j].push_back(i);
            }
        }
    }

    if (is_bipartite()) {
        cout << "TAK" << endl;
        vector<ll> v1, v2;
        for (int i = 0; i < n; i++) {
            if (col[i]) {
                v1.push_back(i + 1);
            } else {
                v2.push_back(i + 1);
            }
        }
        cout << v1.size() << ' ';
        for (auto u: v1) {
            cout << u << ' ';
        }
        cout << endl;
        cout << v2.size() << ' ';
        for (auto u: v2) {
            cout << u << ' ';
        }
    } else {
        cout << "NIE" << endl;
    }

    return 0;
}