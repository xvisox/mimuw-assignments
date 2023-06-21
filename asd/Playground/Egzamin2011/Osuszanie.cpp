#include <bits/stdc++.h>

#define TUP tuple<int, int, int>
#define MAX_N 1001

using namespace std;

int n, m;
char tab[MAX_N][MAX_N];
int dst[MAX_N][MAX_N];
bool visited[MAX_N][MAX_N];
pair<int, int> start_A;
pair<int, int> end_B;

int dRow[4] = {1, -1, 0, 0};
int dCol[4] = {0, 0, 1, -1};

bool isValid(int i, int j) {
    return 0 <= i && i < n && 0 <= j && j < m;
}

void dijkstra() {
    priority_queue<TUP, vector<TUP >, greater<>> q;
    q.push({0, start_A.first, start_A.second});
    dst[start_A.first][start_A.second] = 0;

    int adjx, adjy, w;
    while (!q.empty()) {
        auto [dist, i, j] = q.top();
        q.pop();
        if (visited[i][j]) continue;
        visited[i][j] = true;

        for (int k = 0; k < 4; k++) {
            adjx = i + dRow[k];
            adjy = j + dCol[k];
            w = tab[adjx][adjy] == '#' ? 1 : 0;

            if (isValid(adjx, adjy) && (dst[i][j] + w < dst[adjx][adjy])) {
                dst[adjx][adjy] = dst[i][j] + w;
                q.push({dst[adjx][adjy], adjx, adjy});
            }
        }
    }

}

int main() {
    cin >> n >> m;
    getchar();

    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            tab[i][j] = (char) getchar();
            if (tab[i][j] == 'A') {
                start_A = {i, j};
            }
            if (tab[i][j] == 'B') {
                end_B = {i, j};
            }
            dst[i][j] = INT_MAX;
        }
        getchar();
    }
    dijkstra();
    cout << dst[end_B.first][end_B.second] << endl;
    return 0;
}