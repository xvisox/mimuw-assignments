#include <bits/stdc++.h>

#define WALL '#'
#define MARKED 'X'
#define EMPTY '.'
#define MAX_N 501

using namespace std;
int n, m, k, ile;
pair<int, int> start;
string temp;
char maze[MAX_N][MAX_N];
bool visited[MAX_N][MAX_N];
int dRow[4] = {1, -1, 0, 0};
int dCol[4] = {0, 0, 1, -1};

bool isValid(int i, int j) {
    return 0 <= i && i < n && 0 <= j && j < m;
}

void read() {
    cin >> n >> m >> k;
    for (int i = 0; i < n; i++) {
        cin >> temp;
        for (int j = 0; j < m; j++) {
            maze[i][j] = temp[j];
            if (maze[i][j] == WALL) {
                visited[i][j] = true;
                ile++;
            } else start = {i, j};
        }
    }
}

void bfs() {
    int processed = n * m - ile - k;
    queue<pair<int, int>> q;
    q.push(start);
    visited[start.first][start.second] = true;

    while (!q.empty()) {
        auto [i, j] = q.front();
        q.pop();
        if (processed == 0) {
            maze[i][j] = MARKED;
        } else processed--;

        for (int z = 0; z < 4; z++) {
            int adjx = i + dRow[z];
            int adjy = j + dCol[z];

            if (isValid(adjx, adjy) && !visited[adjx][adjy]) {
                visited[adjx][adjy] = true;
                q.push({adjx, adjy});
            }
        }
    }
}

int main() {
    read();
    bfs();
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            printf("%c", maze[i][j]);
        }
        putchar('\n');
    }

    return 0;
}
