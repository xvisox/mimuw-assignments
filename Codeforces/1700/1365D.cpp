#include <bits/stdc++.h>

#define MAX_N 51

using namespace std;
int cases;
int n, m, good, bad;
char tab[MAX_N][MAX_N];
pair<int, int> start;

int dRow[4] = {0, 0, -1, 1};
int dCol[4] = {1, -1, 0, 0};

bool isValid(int i, int j) {
    return 0 <= i && i < n && 0 <= j && j < m;
}

bool partial() {
    good = 0;
    bad = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            if (tab[i][j] == 'G') {
                for (int k = 0; k < 4; k++) {
                    int adjx = i + dRow[k];
                    int adjy = j + dCol[k];

                    if (isValid(adjx, adjy) && tab[adjx][adjy] == 'B') {
                        cout << "No\n";
                        return true;
                    }
                }
                good++;
                start = {i, j};
            } else if (tab[i][j] == 'B') {
                for (int k = 0; k < 4; k++) {
                    int adjx = i + dRow[k];
                    int adjy = j + dCol[k];

                    if (isValid(adjx, adjy) && tab[adjx][adjy] == '.') {
                        tab[adjx][adjy] = '#';
                    }
                }
                bad++;
            }
        }
    }

    if (isValid(n - 2, m - 1) && tab[n - 2][m - 1] == 'B' || isValid(n - 1, m - 2) && tab[n - 1][m - 2] == 'B') {
        if (good > 0) {
            cout << "No\n";
        } else {
            cout << "Yes\n";
        }
        return true;
    }
    if (good == 0) {
        cout << "Yes\n";
        return true;
    }
    return false;
}

void solve() {
    if (partial()) return;
    int counter = good > 0;
    queue<pair<int, int>> q;
    q.push(start);
    tab[start.first][start.second] = '#';
    bool ended = false;

    while (!q.empty()) {
        auto [i, j] = q.front();
        q.pop();
        if (i == (n - 1) && j == (m - 1)) ended = true;

        for (int k = 0; k < 4; k++) {
            int adjx = i + dRow[k];
            int adjy = j + dCol[k];

            if (isValid(adjx, adjy) && tab[adjx][adjy] != '#') {
                if (tab[adjx][adjy] == 'G') counter++;
                tab[adjx][adjy] = '#';
                q.push({adjx, adjy});
            }
        }
    }

    if (good == counter && ended) {
        cout << "Yes\n";
    } else cout << "No\n";
}

int main() {
    cin >> cases;
    string temp;
    for (int i = 0; i < cases; i++) {
        scanf("%d %d", &n, &m);
        for (int k = 0; k < n; k++) {
            cin >> temp;
            for (int l = 0; l < m; l++) {
                tab[k][l] = temp[l];
            }
        }
        solve();
    }

    return 0;
}