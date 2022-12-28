#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define ll long long
#define endl '\n'
using namespace std;

constexpr int MAX_N = 5e5 + 1;
int n, m, q;

bitset<MAX_N> car, visited;
vector<int> adj[MAX_N];
int link[MAX_N], sajz[MAX_N];
unordered_map<int, vector<int>> neigh;

vector<pair<int, int>> queries;
unordered_map<int, int> queried;
bitset<MAX_N> skip;

int find(int x) {
    int start = x;
    while (x != link[x]) {
        x = link[x];
    }
    return (link[start] = x);
}

void unite(int a, int b) {
    a = find(a);
    b = find(b);
    if (a == b) return;

    if (sajz[a] < sajz[b]) swap(a, b);
    sajz[a] += sajz[b];
    link[b] = a;
}

void dfs(int v, int s) {
    visited[v] = true;

    for (int u: adj[v]) {
        if (!visited[u] && !car[u]) {
            unite(s, u); // wrzucamy do jednego zbioru
            dfs(u, s);
        } else if (car[u]) {
            neigh[u].push_back(s); // mówimy, że zbiór s sąsiaduje z samochodem u
        }
    }
}

void solve() {
    int ai, bi;
    for (int i = 0; i < q; ++i) {
        tie(ai, bi) = queries[i];
        // jeśli cos stoi na miejscu parkingowym
        // to nie ma co szukać
        if (skip[i] || car[bi]) {
            cout << "NIE\n";
            continue;
        }

        int bi_set = find(bi); // szukamy zbioru, do którego należy parking
        auto &ai_sets = neigh[ai]; // szukamy zbiorów, które sąsiadują z samochodem

        for (auto s: ai_sets) {
            if (find(s) == bi_set) {
                cout << "TAK\n";
                car[ai] = false; // usuwamy auto

                for (int &u: adj[ai]) {
                    if (car[u]) {
                        neigh[u].push_back(bi_set); // dodajemy nowe sąsiedztwo
                    } else {
                        unite(ai, u); // łączymy zbiory
                    }
                }
                break;
            }
        }
        if (car[ai]) cout << "NIE\n";
    }
}

int main() {
    FASTIO;
    cin >> n >> m;
    int x;
    for (int i = 1; i <= n; ++i) {
        cin >> x;

        car[i] = x;
        sajz[i] = 1;
        link[i] = i;
    }

    int ai, bi;
    while (m--) {
        cin >> ai >> bi;
        adj[ai].push_back(bi);
        adj[bi].push_back(ai);
    }

    for (int i = 1; i <= n; ++i) {
        // tworzymy nowy zbiór, jeśli nie należy już do
        // jakiegoś i ten zbiór nie może zawierać samochodu
        if (!visited[i] && !car[i]) {
            dfs(i, i);
        }
    }

    // omijamy pytania, które nie mają sensu
    cin >> q;
    for (int i = 0; i < q; ++i) {
        cin >> ai >> bi;
        queries.emplace_back(ai, bi);

        if (queried.find(ai) == queried.end()) {
            queried[ai] = i;
        } else {
            skip[queried[ai]] = true;
            queried[ai] = i;
        }
    }

    solve();

    return 0;
}