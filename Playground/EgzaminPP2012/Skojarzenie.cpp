#include <bits/stdc++.h>

#define MAX_N 300'001

using namespace std;
int n, root;
vector<pair<int, int>> adj[MAX_N];
int pom[MAX_N][2];

void read() {
    cin >> n;
    int ai, bi, wi;
    for (int i = 0; i < n - 1; i++) {
        scanf("%d %d %d", &ai, &bi, &wi);
        adj[ai].emplace_back(bi, wi);
        adj[bi].emplace_back(ai, wi);
    }

    root = 1; // ?
}

void dfs(int s, int last) {
    if (adj[s].size() == 1 && s != root) return;

    for (auto v: adj[s]) {
        if (v.first != last) dfs(v.first, s);
    }

    int sum = 0;
    for (auto v: adj[s]) {
        if (v.first != last) {
            sum += max(pom[v.first][0], pom[v.first][1]);
        }
    }
    pom[s][1] = sum;

    int temp;
    for (auto v: adj[s]) {
        if (v.first != last) {
            temp = sum - max(pom[v.first][0], pom[v.first][1]) + v.second + pom[v.first][1];
            pom[s][0] = max(temp, pom[s][0]);
        }
    }
}

int main() {
    read();
    if (n < 3) {
        cout << adj[1][0].second << endl;
    } else {
        dfs(root, 0);
        cout << max(pom[root][0], pom[root][1]);
    }

    return 0;
}