#include <bits/stdc++.h>

using namespace std;

int n, temp, i, j, k;
int result[201][201];
bool changed[201][201];

int main() {
    cin >> n;
    for (i = 0; i < n; i++)
        for (j = 0; j < n; j++) {
            cin >> result[i][j];
        }

    for (k = 0; k < n; k++)
        for (i = 0; i < n; i++) {
            if (i == k) continue;
            for (j = i + 1; j < n; j++) {
                if (k == j) continue;
                temp = result[i][k] + result[k][j];
                if (temp <= result[i][j]) {
                    result[i][j] = temp;
                    changed[i][j] = true;
                }
            }
        }
    for (i = 0; i < n; i++)
        for (j = i + 1; j < n; j++)
            if (!changed[i][j]) printf("%d %d\n", i + 1, j + 1);
    return 0;
}