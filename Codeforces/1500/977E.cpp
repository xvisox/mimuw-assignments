#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
using namespace std;
constexpr int MAX_N = 2 * 1e5 + 1;
int n, m;
int link[MAX_N], sajz[MAX_N];
vector<int> adj[MAX_N];
unordered_set<int> marked;

int find(int x) {
    int start = x;
    while (x != link[x]) x = link[x];
    return (link[start] = x);
}

void unite(int a, int b) {
    a = find(a);
    b = find(b);
    if (a == b) {
        marked.insert(a);
    }

    if (sajz[a] < sajz[b]) swap(a, b);
    link[b] = a;
    sajz[a] += sajz[b];
}

bool dfs(int s, int curr, int last) {
    if (adj[curr].size() != 2) return false;

    for (auto el: adj[curr]) {
        if (el != last) {
            if (el == s && curr != s) return true;
            else {
                return dfs(s, el, curr);
            }
        }
    }
}

int main() {
    FASTIO;
    cin >> n >> m;
    for (int i = 1; i <= n; i++) {
        sajz[i] = 1;
        link[i] = i;
    }
    int a, b;
    for (int i = 0; i < m; i++) {
        cin >> a >> b;
        unite(a, b);
        adj[a].push_back(b);
        adj[b].push_back(a);
    }

    int counter = 0;
    for (auto el: marked) {
        if (dfs(el, el, -1)) counter++;
    }
    cout << counter << '\n';

    return 0;
}