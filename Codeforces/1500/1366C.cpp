#include <bits/stdc++.h>

#define MAX_N 31

using namespace std;
int n, t, m;
int dp[MAX_N][MAX_N];
bitset<MAX_N> visited[MAX_N];
int counter[(2 * MAX_N) + 1][2];

int dRow[2] = {0, 1};
int dCol[2] = {1, 0};

bool isValid(int i, int j) {
    return 0 <= i && i < n && 0 <= j && j < m;
}

void bfs() {
    queue<tuple<int, int, int>> q;
    q.push({0, 0, 0});
    visited[0][0] = true;

    while (!q.empty()) {
        auto [i, j, dst] = q.front();
        counter[dst][dp[i][j]]++;
        q.pop();

        for (int k = 0; k < 2; k++) {
            int adjx = i + dRow[k];
            int adjy = j + dCol[k];
            if (isValid(adjx, adjy)) {
                if (visited[adjx][adjy]) continue;
                visited[adjx][adjy] = true;
                q.push({adjx, adjy, dst + 1});
            }
        }

    }
}

int main() {
    cin >> t;
    for (int k = 0; k < t; k++) {
        scanf("%d %d", &n, &m);
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < m; j++) {
                scanf("%d", &dp[i][j]);
            }
            visited[i].reset();
        }
        fill_n(&counter[0][0], ((2 * MAX_N) + 1) * 2, 0);

        bfs();
        int dst = (n + m - 2);
        int sum = 0;
        int dupa = (dst / 2) + (dst % 2 == 1);
        for (int i = 0; i < dupa; i++) {
            if (counter[i][1] + counter[dst - i][1] > counter[i][0] + counter[dst - i][0]) {
                sum += (counter[i][0] + counter[dst - i][0]);
            } else {
                sum += (counter[i][1] + counter[dst - i][1]);
            }
        }
        cout << sum << '\n'; // eeee
    }

    return 0;
}