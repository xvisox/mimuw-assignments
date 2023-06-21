#include <bits/stdc++.h>

#define ll long long
#define MAX_N 500001

using namespace std;

ll koszt[MAX_N];
unordered_set<int> adj[MAX_N];
vector<pair<ll, int>> sortowane; // {val, idx}
vector<int> removed; // usunięte wierzchołki

int n, m;
ll result = LONG_LONG_MAX;

ll ll_min(ll a, ll b) {
    return a < b ? a : b;
}

void read() {
    cin >> n;
    for (int i = 1; i <= n; i++) {
        scanf("%lld", &koszt[i]);
        sortowane.emplace_back(koszt[i], i);
    }
    sort(sortowane.begin(), sortowane.end());

    cin >> m;
    int ai, bi, ki;
    for (int i = 0; i < m; i++) {
        scanf("%d %d %d", &ai, &bi, &ki);
        adj[ai].insert(bi);
        adj[bi].insert(ai);

        result = ll_min(result, koszt[ai] + koszt[bi] + (2 * ki));
    }
}

void solve() {
    int v = sortowane[0].second;
    removed.push_back(v);

    int i = 1;
    while (i < sortowane.size()) {
        v = sortowane[i].second; // kolejna do usunięcia.
        auto end = adj[v].end();
        for (auto rmv: removed) {
            if (adj[v].find(rmv) == end) {
                result = ll_min(result, koszt[v] + koszt[rmv]);
                break;
            }
        }
        removed.push_back(v);
        i++;
    }
}

int main() {
    read();
    solve();
    cout << result << endl;
    return 0;
}