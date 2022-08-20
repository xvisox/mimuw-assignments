#include <bits/stdc++.h>

#define MAX_N 500005

using namespace std;

int n;
long long ceny[MAX_N];
int add_left[MAX_N], add_right[MAX_N];
vector<int> adj[MAX_N];
vector<int> result;
bool visited[MAX_N];

void dfs(int s) {
    visited[s] = true;
    for (auto v: adj[s]) {
        if (!visited[v]) dfs(v);
    }
    result.push_back(s);
}

void createGraph() {
    for (int i = 2; i <= n; i++) {
        if (add_left[i] > add_right[i - 1]) {
            adj[i - 1].push_back(i);
        } else {
            adj[i].push_back(i - 1);
        }
    }
}

void read() {
    cin >> n;
    for (int i = 1; i <= n; i++) {
        scanf("%d", &ceny[i]);
    }
    for (int i = 1; i <= n - 1; i++) {
        scanf("%d", &add_right[i]);
    }
    for (int i = 2; i <= n; i++) {
        scanf("%d", &add_left[i]);
    }
}

int main() {
    read();
    createGraph();

    for (int i = 1; i <= n; i++) {
        if (!visited[i]) dfs(i);
    }
    reverse(result.begin(), result.end());

    long long minCost = 0, idx;
    for (int i = 0; i < n; i++) {
        idx = result[i];

        minCost += ceny[idx];
        ceny[idx - 1] += add_left[idx];
        ceny[idx + 1] += add_right[idx];
    }

    cout << minCost << '\n';
    cout << result[0];
    for (int i = 1; i < n; i++) {
        cout << ' ' << result[i];
    }
    return 0;
}