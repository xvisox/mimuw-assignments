#include <bits/stdc++.h>

#define TUP tuple<int, int, int>
#define MAX_N 501

using namespace std;

int n, m, h;
bool processed[MAX_N][MAX_N];
int dst[MAX_N][MAX_N];

int main() {
    scanf("%d %d %d", &n, &m, &h);
    int tab[n][m];
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            scanf("%d", &tab[i][j]);
            dst[i][j] = INT_MAX;
        }
    }

    priority_queue<TUP, vector<TUP >, greater<>> q; // {weight, i, j}
    dst[0][0] = 0;
    q.push({0, 0, 0});

    int adjx, adjy, weight, temp;
    int currentWeight, adjWeight;
    while (!q.empty()) {
        auto [distance, i, j] = q.top();
        q.pop();
        if (processed[i][j]) continue;
        processed[i][j] = true;

        currentWeight = tab[i][j];
        for (int x = -2; x <= 2; x++) {
            adjx = i + x;
            if (!(0 <= adjx && adjx < n)) continue;
            for (int y = -2; y <= 2; y++) {
                adjy = j + y;
                if (!(0 <= adjy && adjy < m)) continue;
                adjWeight = tab[adjx][adjy];

                temp = abs(currentWeight - adjWeight);
                if (temp <= h) {
                    weight = 1;
                } else {
                    weight = temp - h + 1;
                }

                if (dst[i][j] + weight < dst[adjx][adjy]) {
                    if (weight > 1) {
                        if (tab[i][j] > tab[adjx][adjy]) {
                            tab[i][j] = currentWeight - weight;
                        } else {
                            tab[i][j] = currentWeight + weight;
                        }
                    }

                    dst[adjx][adjy] = dst[i][j] + weight;
                    q.push({dst[adjx][adjy], adjx, adjy});
                }
            }
        }
    }

    cout << dst[n - 1][m - 1] << endl;
    return 0;
}