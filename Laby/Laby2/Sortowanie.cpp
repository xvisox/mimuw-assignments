#include<bits/stdc++.h>

#define MOD 1000000000L
using namespace std;

// Wyjaśnienie rozwiązania:
// Tworzymy tablice n * n, która będzie zawierała dane podciągi:
// Niech n = 4, i A = {1,2,3,4}. Wtedy:
//     1  2  3  4
// 1   1
// 2      1
// 3         1
// 4            1
// W tablicy dp[i][j] oznacza na ile sposobów, można uzyskać podciąg [i, j].
// Teraz w łatwy sposób możemy policzyć na ile sposobów otrzymamy kolejny podciąg np:
// 123 uzyskamy przez 23 <- 1 oraz 12 <- 3. Tylko w ten sposób nie jesteśmy w stanie kontrolować,
// jaki był poprzednio dodany poprzednik.
// Złożoność:
// 1) Czas O(n^2)
// 2) Pamięć O(n^2)
int main() {
    int n, i, j, k;
    bool poprzednikLewy = false;
    cin >> n;
    int tab[n], dp[n][n];
    memset(&dp[0][0], 0, sizeof(dp));
    for (i = 0; i < n; i++) {
        cin >> tab[i];
        dp[i][i] = 1;
    }

    // Sprawdzenie inwersji.
    j = 0;
    k = 1;
    while (k < n) {
        dp[j][k] = tab[j] < tab[k];
        dp[k][j] = tab[j] < tab[k];
        k++;
        j++;
    }

    // Główna pętla nr 1.
    for (i = 2; i < n; i++) {
        j = 0, k = i;
        while (k < n) {
            if (poprzednikLewy) {
                if (dp[j][k - 1] != 0 && tab[j] < tab[k]) dp[j][k] += dp[j][k - 1];
                if (dp[j + 1][k] != 0 && tab[j] < tab[j + 1]) dp[j][k] += dp[j + 1][k];
            } else {
                if (dp[j][k - 1] != 0 && tab[k - 1] < tab[k]) dp[j][k] += dp[j][k - 1];
                if (dp[j + 1][k] != 0 && tab[j] < tab[k]) dp[j][k] += dp[j + 1][k];
            }
            j++;
            k++;
        }
        poprzednikLewy = !poprzednikLewy;
    }

    poprzednikLewy = true;
    // Główna pętla nr 2.
    for (i = 2; i < n; i++) {
        j = 0, k = i;
        while (k < n) {
            if (poprzednikLewy) {
                if (dp[k - 1][j] != 0 && tab[j] < tab[k]) dp[k][j] += dp[k - 1][j];
                if (dp[k][j + 1] != 0 && tab[j] < tab[j + 1]) dp[k][j] += dp[k][j + 1];
            } else {
                if (dp[k - 1][j] != 0 && tab[k - 1] < tab[k]) dp[k][j] += dp[k - 1][j];
                if (dp[k][j + 1] != 0 && tab[j] < tab[k]) dp[k][j] += dp[k][j + 1];
            }
            j++;
            k++;
        }
        poprzednikLewy = !poprzednikLewy;
    }

    for (i = 0; i < n; i++) {
        for (j = 0; j < n; j++) {
            cout << dp[i][j] << ' ';
        }
        cout << endl;
    }

    return dp[0][n - 1] + dp[n - 1][0];
}