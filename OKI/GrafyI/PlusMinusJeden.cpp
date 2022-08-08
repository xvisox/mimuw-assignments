#include <bits/stdc++.h>

using namespace std;

int n, m, k, xi, yi;
constexpr int MAX = 2e5 + 1;
constexpr int MAX_N = 1e5;
bool used[MAX];
bool visited[MAX];
int it[MAX], kolumny[MAX_N], wiersze[MAX_N];
vector<pair<int, int>> adj[MAX];
vector<int> cycle;

inline size_t key(int i, int j) { return (size_t) i << 32 | (unsigned int) j; }

void euler(int v) {
    int w, idx;
    for (; it[v] < adj[v].size(); it[v]++) {
        w = adj[v][it[v]].first;
        idx = adj[v][it[v]].second;
        if (used[idx]) continue;
        used[idx] = true;
        euler(w);
    }
    cycle.push_back(v);
}

int main() {
    cin >> n;
    cin >> m;
    cin >> k;
    vector<pair<int, int >> input;
    unordered_map<size_t, int> mapka;

    for (int i = 0; i < k; i++) {
        scanf("%d %d", &xi, &yi);
        wiersze[xi]++;
        kolumny[yi]++;

        input.emplace_back(xi, yi + n);
        adj[xi].emplace_back(yi + n, i);
        adj[yi + n].emplace_back(xi, i);
    }

    for (int i = 0; i < 2 * n; i++) {
        if (adj[i].size() % 2 == 1) {
            cout << "NIE" << '\n';
            return 0;
        }
    }
    cout << "TAK" << '\n';

    for (auto element: input) {
        if (!visited[element.first]) {
            euler(element.first);
            for (int i = 0; i < cycle.size() - 1; i++) {
                if (cycle[i] < cycle[i + 1])
                    mapka[key(cycle[i], cycle[i + 1])] = -1;
                else
                    mapka[key(cycle[i + 1], cycle[i])] = 1;
            }
            cycle.clear();
        }
        if (!visited[element.second]) {
            euler(element.second);
            for (int i = 0; i < cycle.size() - 1; i++) {
                if (cycle[i] < cycle[i + 1])
                    mapka[key(cycle[i], cycle[i + 1])] = -1;
                else
                    mapka[key(cycle[i + 1], cycle[i])] = 1;
            }
            cycle.clear();
        }
    }

    for (auto element: input) {
        cout << mapka[key(element.first, element.second)] << '\n';
    }
    return 0;
}