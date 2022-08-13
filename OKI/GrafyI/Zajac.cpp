#include <bits/stdc++.h>

using namespace std;

constexpr int MAX_N = 1000;

int n, m;
char tab[MAX_N + 1][MAX_N + 1];

int dRow[8] = {1, 1, -1, -1, 2, 2, -2, -2};
int dCol[8] = {2, -2, 2, -2, 1, -1, 1, -1};

#define TUP tuple<int, int, int>

bool isValid(int i, int j) {
    return 0 <= i && i < n && 0 <= j && j < m;
}

int main() {
    cin >> n;
    cin >> m;
    string temp;
    queue<TUP > q;
    for (int i = 0; i < n; i++) {
        cin >> temp;
        for (int j = 0; j < m; j++) {
            tab[i][j] = temp[j];
            if (tab[i][j] == 'z') {
                q.push({i, j, 0});
                tab[i][j] = 'x';
            }
        }
    }

    int k, adjx, adjy;
    while (!q.empty()) {
        auto [i, j, dst] = q.front();
        q.pop();

        for (k = 0; k < 8; k++) {
            adjx = i + dRow[k];
            adjy = j + dCol[k];

            if (isValid(adjx, adjy) && tab[adjx][adjy] != 'x') {
                if (tab[adjx][adjy] == 'n') {
                    cout << dst + 1 << '\n';
                    return 0;
                }
                q.push({adjx, adjy, dst + 1});
                tab[adjx][adjy] = 'x';
            }
        }
    }
    cout << "NIE\n";
    return 0;
}