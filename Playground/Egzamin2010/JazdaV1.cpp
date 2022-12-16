#include <bits/stdc++.h>

#define FASTIO ios_base::sync_with_stdio(false); cin.tie(0), cout.tie(0)
#define endl '\n'
#define MAX_N 300001

using namespace std;
int n, m;
vector<pair<int, int>> adj[MAX_N];
set<int> unvisited;
set<int> recursive_stack;
set<int>::iterator it;

void read() {
    cin >> n >> m;
    int ai, bi, ci;

    for (int i = 0; i < m; i++) {
        cin >> ai >> bi >> ci;
        adj[ai].emplace_back(bi, ci);
    }
}

void dfs(int s) {
    recursive_stack.insert(s);
    unvisited.erase(s);

    for (auto v: adj[s]) {

        it = recursive_stack.lower_bound(v.first);
        if (it != recursive_stack.end() && *it <= v.second) {
            cout << "TAK" << endl;
            exit(0);
        }

        it = unvisited.lower_bound(v.first);
        while (it != unvisited.end() && *it <= v.second) {
            dfs(*it);
            it = unvisited.lower_bound(v.first);
        }

    }

    recursive_stack.erase(s);
}

int main() {
    FASTIO;
    read();

    for (int v = 1; v <= n; v++) {
        unvisited.insert(v);
    }

    while (!unvisited.empty()) {
        dfs(*unvisited.begin());
    }
    cout << "NIE" << endl;

    return 0;
}
