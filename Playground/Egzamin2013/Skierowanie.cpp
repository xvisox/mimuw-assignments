#include <bits/stdc++.h>

#define MAX_N 500001
#define IN 'i'
#define OUT 'o'
#define UNDF 'u'

using namespace std;
char ozn[MAX_N];
vector<int> adj[MAX_N];
int n, m;
bool res = true;

void read() {
    cin >> n >> m;
    int ai, bi;
    for (int i = 0; i < m; i++) {
        scanf("%d %d", &ai, &bi);
        adj[ai].push_back(bi);
        adj[bi].push_back(ai);
    }
}

void bfs(int s) {
    queue<pair<int, char>> q;
    q.push({s, OUT});
    ozn[s] = OUT;

    int v;
    char typ, nextTyp;
    while (!q.empty()) {
        v = q.front().first;
        typ = q.front().second;
        nextTyp = typ == IN ? OUT : IN;
        q.pop();

        for (auto u: adj[v]) {
            if (ozn[u] == UNDF) {
                ozn[u] = nextTyp;
                q.push({u, nextTyp});
            } else if (ozn[u] != nextTyp) {
                res = false;
                return;
            }
        }
    }

}

int main() {
    read();
    fill_n(&ozn[0], n + 1, UNDF);

    for (int i = 1; i <= n && res; i++) {
        if (ozn[i] == UNDF) {
            bfs(i);
        }
    }

    if (res) cout << "TAK" << endl;
    else cout << "NIE" << endl;
    return 0;
}