#include <bits/stdc++.h>

using namespace std;

#define INF INT_MAX

bool isValid(int i, int j, int n, int m) {
    return 0 <= i && i < n && 0 <= j && j < m;
}

int dRow[] = {-1, 0, 1, 0};
int dCol[] = {0, 1, 0, -1};

int main() {
    int n, m;
    cin >> n;
    cin >> m;
    int distance[n][m];
    queue<tuple<int, int, int>> q;
    string temp;
    for (int i = 0; i < n; i++) {
        cin >> temp;
        for (int j = 0; j < m; j++) {
            if (temp[j] == '1') {
                distance[i][j] = 0;
                q.push(make_tuple(i, j, 0));
            } else {
                distance[i][j] = INF;
            }
        }
    }

    int k, adjx, adjy;
    while (!q.empty()) {
        auto [i, j, len] = q.front();
        q.pop();

        for (k = 0; k < 4; k++) {
            adjx = i + dRow[k];
            adjy = j + dCol[k];
            if (isValid(adjx, adjy, n, m)) {
                if (distance[adjx][adjy] > len + 1) {
                    distance[adjx][adjy] = len + 1;
                    q.push(make_tuple(adjx, adjy, len + 1));
                }
            }
        }
    }

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            cout << distance[i][j] << ' ';
        }
        cout << '\n';
    }
    return 0;
}