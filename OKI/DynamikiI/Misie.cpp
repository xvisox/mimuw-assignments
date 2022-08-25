#include <bits/stdc++.h>

#define A1 "A1"
#define A2 "A2"
#define B1 "B1"
#define B2 "B2"

using namespace std;

constexpr int MOD = 1e6;
constexpr int MAX_N = 39;
constexpr int ALL = 4;

int n_A1, n_A2, n_B1, n_B2, n;
int dp[ALL][MAX_N][MAX_N][MAX_N][ALL][ALL];
string intToMisie[4] = {A1, A2, B1, B2};

bool isValid(string p, string q, string r) {
    return (p[0] == q[0] && q[0] == r[0]) || (p[1] == q[1] && q[1] == r[1]);
}

void init() {
    dp[1][1][0][0][0][1] = 1; // A1, A2
    dp[1][0][1][0][0][2] = 1; // A1, B1
    dp[1][0][0][1][0][3] = 1; // A1, B2
    dp[0][1][1][0][1][2] = 1; // A2, B1
    dp[0][1][0][1][1][3] = 1; // A2, B2
    dp[0][0][1][1][2][3] = 1; // B1, B2

    dp[1][1][0][0][1][0] = 1; //  A2, A1
    dp[1][0][1][0][2][0] = 1; //  B1, A1
    dp[1][0][0][1][3][0] = 1; //  B2, A1
    dp[0][1][1][0][2][1] = 1; //  B1, A2
    dp[0][1][0][1][3][1] = 1; //  B2, A2
    dp[0][0][1][1][3][2] = 1; //  B2, B1

    dp[2][0][0][0][0][0] = 1; // A1, A1
    dp[0][2][0][0][1][1] = 1; // A2, A2
    dp[0][0][2][0][2][2] = 1; // B1, B1
    dp[0][0][0][2][3][3] = 1; // B2, B2
}

int iv(int r, const string &mis) {
    return intToMisie[r] == mis ? 1 : 0;
}

void cpy() {
    for (int j = 0; j <= n_A2; j++)
        for (int k = 0; k <= n_B1; k++)
            for (int l = 0; l <= n_B2; l++)
                for (int q = 0; q < 4; q++)
                    for (int r = 0; r < 4; r++) {
                        dp[2][j][k][l][q][r] = dp[3][j][k][l][q][r];
                    }
}

int main() {
    scanf("%d %d %d %d", &n_A1, &n_A2, &n_B1, &n_B2);
    n = n_A1 + n_A2 + n_B1 + n_B2;
    if (n == 1) {
        cout << 1 << endl;
        return 0;
    }
    init();

    for (int i = 0; i <= n_A1; i++) {
        for (int j = 0; j <= n_A2; j++)
            for (int k = 0; k <= n_B1; k++)
                for (int l = 0; l <= n_B2; l++)
                    for (int q = 0; q < 4; q++) // p, q, r
                        for (int r = 0; r < 4; r++) {
                            if (iv(r, A1) && i == 0 || iv(r, A2) && j == 0 || iv(r, B1) && k == 0 || iv(r, B2) && l == 0) continue;

                            for (int p = 0; p < 4; p++) {
                                if (i + j + k + l > 2 && !isValid(intToMisie[p], intToMisie[q], intToMisie[r])) {
                                    dp[i][j][k][l][q][r] += dp[i - iv(r, A1)][j - iv(r, A2)][k - iv(r, B1)][l - iv(r, B2)][p][q];
                                    dp[i][j][k][l][q][r] %= MOD;
                                }
                            }
                        }
    }

    long long result = 0;
    for (int q = 0; q < 4; q++)
        for (int r = 0; r < 4; r++) {
            result += dp[n_A1][n_A2][n_B1][n_B2][q][r];
            result %= MOD;
        }
    cout << result << endl;
    return 0;
}